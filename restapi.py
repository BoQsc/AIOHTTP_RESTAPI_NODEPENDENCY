import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta

from aiohttp import web

# --- Configuration ---
HOST = '127.0.0.1'
PORT = 8080
DATABASE_FILE = 'blog_api_db.json'
SECRET_KEY = b'your_very_secret_key_for_hmac_do_not_share' # Keep this secret!
TOKEN_EXPIRATION_MINUTES = 60

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- In-memory "Database" ---
# Represents our "tables"
db = {
    "users": {},  # user_id: {username, password_hash, created_at}
    "posts": {},  # post_id: {title, text, owner_id, editor_id, created_at, updated_at}
    "comments": {} # comment_id: {post_id, user_id, text, created_at, updated_at}
}
next_user_id = 1
next_post_id = 1
next_comment_id = 1

# --- Utility Functions ---

def generate_password_hash(password):
    """Generates a simple SHA256 hash for the password."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(user_id):
    """
    Generates a simple, non-cryptographic token for demonstration.
    DO NOT USE IN PRODUCTION. This is for the 'no external libraries' constraint.
    """
    expiration_time = int(time.time() + TOKEN_EXPIRATION_MINUTES * 60)
    payload = f"{user_id}:{expiration_time}"
    signature = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    token_data = f"{payload}.{signature}"
    return base64.urlsafe_b64encode(token_data.encode()).decode()

def decode_token(token):
    """
    Decodes and validates the simple token.
    DO NOT USE IN PRODUCTION.
    Returns user_id if valid, None otherwise.
    """
    try:
        token_data_encoded = base64.urlsafe_b64decode(token).decode()
        payload_str, signature = token_data_encoded.rsplit('.', 1)
        
        # Verify signature
        expected_signature = hmac.new(SECRET_KEY, payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            return None # Invalid signature

        user_id_str, expiration_time_str = payload_str.split(':', 1)
        user_id = int(user_id_str)
        expiration_time = int(expiration_time_str)

        if time.time() > expiration_time:
            logger.warning(f"Token for user {user_id} expired.")
            return None # Token expired

        # Check if user actually exists in the database
        if user_id not in db["users"]:
            logger.warning(f"Token with user_id {user_id} refers to non-existent user.")
            return None

        return user_id
    except Exception as e:
        logger.error(f"Token decoding failed: {e}")
        return None

async def authenticate_middleware(app, handler):
    async def middleware_handler(request):
        request.user_id = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            user_id = decode_token(token)
            if user_id:
                request.user_id = user_id
            else:
                # If token is invalid or expired, allow it to pass but without user_id
                # The route handlers can then return 401 if authentication is required.
                logger.debug(f"Invalid or expired token provided: {token}")
        return await handler(request)
    return middleware_handler

# --- Data Persistence (Simple JSON) ---

def load_db():
    global db, next_user_id, next_post_id, next_comment_id
    try:
        with open(DATABASE_FILE, 'r') as f:
            loaded_db = json.load(f)
            db = loaded_db
            next_user_id = max(db["users"].keys(), default=0, key=int) + 1
            next_post_id = max(db["posts"].keys(), default=0, key=int) + 1
            next_comment_id = max(db["comments"].keys(), default=0, key=int) + 1
        logger.info("Database loaded from file.")
    except FileNotFoundError:
        logger.info("No existing database file found. Initializing empty database.")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding database file: {e}. Starting with empty database.")
        # Reset db in case of corruption
        db = {
            "users": {},
            "posts": {},
            "comments": {}
        }
        next_user_id = 1
        next_post_id = 1
        next_comment_id = 1
    except Exception as e:
        logger.error(f"An unexpected error occurred loading database: {e}. Starting with empty database.")
        db = {
            "users": {},
            "posts": {},
            "comments": {}
        }
        next_user_id = 1
        next_post_id = 1
        next_comment_id = 1


def save_db():
    try:
        # Convert integer keys to strings for JSON serialization
        serializable_db = {
            "users": {str(k): v for k, v in db["users"].items()},
            "posts": {str(k): v for k, v in db["posts"].items()},
            "comments": {str(k): v for k, v in db["comments"].items()}
        }
        with open(DATABASE_FILE, 'w') as f:
            json.dump(serializable_db, f, indent=2)
        logger.info("Database saved to file.")
    except Exception as e:
        logger.error(f"Error saving database to file: {e}")

# --- Validators ---

def validate_user_input(username, password):
    if not username or not password:
        return False, "Username and password are required."
    if len(username) < 3:
        return False, "Username too short (min 3 characters)."
    if len(username) > 50:
        return False, "Username too long (max 50 characters)."
    if len(password) < 6:
        return False, "Password too short (min 6 characters)."
    return True, None

def validate_post_input(title, text):
    if not title or not text:
        return False, "Title and text are required."
    if len(title) < 5:
        return False, "Title too short (min 5 characters)."
    if len(title) > 255:
        return False, "Title too long (max 255 characters)."
    if len(text) < 10:
        return False, "Post text too short (min 10 characters)."
    return True, None

def validate_comment_input(text):
    if not text:
        return False, "Comment text is required."
    if len(text) < 3:
        return False, "Comment text too short (min 3 characters)."
    if len(text) > 500:
        return False, "Comment text too long (max 500 characters)."
    return True, None

# --- API Handlers ---

async def root_handler(request):
    """Handles the root endpoint, providing API info."""
    return web.json_response({
        "message": "Welcome to the Blog API!",
        "endpoints": {
            "register": "POST /api/v1/register",
            "login": "POST /api/v1/login",
            "posts": "GET /api/v1/posts",
            "post_detail": "GET /api/v1/posts/{id}",
            "create_post": "POST /api/v1/posts",
            "update_post": "PATCH /api/v1/posts/{id}",
            "delete_post": "DELETE /api/v1/posts/{id}",
            "comments_on_post": "GET /api/v1/posts/{post_id}/comments",
            "add_comment": "POST /api/v1/posts/{post_id}/comments",
            "update_comment": "PATCH /api/v1/comments/{comment_id}",
            "delete_comment": "DELETE /api/v1/comments/{comment_id}"
        }
    })

async def register_user(request):
    """Registers a new user."""
    global next_user_id
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')

        is_valid, error_msg = validate_user_input(username, password)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)

        # Check if username already exists
        if any(u['username'] == username for u in db["users"].values()):
            return web.json_response({"status": "error", "message": f"Username '{username}' already exists."}, status=400)

        user_id = next_user_id
        next_user_id += 1
        password_hash = generate_password_hash(password)
        created_at = int(time.time())

        db["users"][user_id] = {
            "username": username,
            "password_hash": password_hash,
            "created_at": created_at
        }
        token = create_token(user_id)
        save_db()
        logger.info(f"User '{username}' created with ID: {user_id}")
        return web.json_response({
            "status": "success",
            "message": "User registered successfully.",
            "user_id": user_id,
            "token": token
        }, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error during user registration:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def login_user(request):
    """Logs in a user and provides an authentication token."""
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')

        is_valid, error_msg = validate_user_input(username, password)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)

        user_found = None
        for user_id, user_data in db["users"].items():
            if user_data['username'] == username:
                user_found = user_data
                user_found_id = user_id
                break

        if not user_found or user_found['password_hash'] != generate_password_hash(password):
            return web.json_response({"status": "error", "message": "Invalid username or password."}, status=401)

        token = create_token(user_found_id)
        logger.info(f"User {user_found_id} authenticated.")
        return web.json_response({
            "status": "success",
            "message": "Login successful.",
            "token": token
        })
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error during user login:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def create_post(request):
    """Creates a new blog post."""
    global next_post_id
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    try:
        data = await request.json()
        title = data.get('title')
        text = data.get('text')

        is_valid, error_msg = validate_post_input(title, text)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)

        post_id = next_post_id
        next_post_id += 1
        current_time = int(time.time())

        new_post = {
            "id": post_id,
            "title": title,
            "text": text,
            "owner_id": request.user_id,
            "editor_id": request.user_id, # Initial editor is the owner
            "created_at": current_time,
            "updated_at": current_time
        }
        db["posts"][post_id] = new_post
        save_db()
        logger.info(f"Post '{title}' created by user {request.user_id} with ID: {post_id}")
        return web.json_response({"status": "success", "data": new_post}, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error creating post:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def list_posts(request):
    """Lists all blog posts."""
    # Optional pagination
    page = int(request.query.get('page', 1))
    limit = int(request.query.get('limit', 10))

    if page < 1 or limit < 1:
        return web.json_response({"status": "error", "message": "Page and limit must be positive integers."}, status=400)

    start_index = (page - 1) * limit
    end_index = start_index + limit

    all_posts = list(db["posts"].values())
    # Sort posts by updated_at or created_at descending
    sorted_posts = sorted(all_posts, key=lambda x: x['updated_at'] if 'updated_at' in x else x['created_at'], reverse=True)
    paginated_posts = sorted_posts[start_index:end_index]

    return web.json_response({
        "status": "success",
        "data": paginated_posts,
        "page": page,
        "limit": limit,
        "total_posts": len(all_posts)
    })

async def get_post(request):
    """Retrieves a single blog post by ID."""
    post_id = int(request.match_info['id'])
    post = db["posts"].get(post_id)
    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)
    return web.json_response({"status": "success", "data": post})

async def update_post(request):
    """Updates an existing blog post."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    post_id = int(request.match_info['id'])
    post = db["posts"].get(post_id)

    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    if post['owner_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only edit your own posts."}, status=403)

    try:
        data = await request.json()
        title = data.get('title', post['title']) # Use existing if not provided
        text = data.get('text', post['text'])   # Use existing if not provided

        # Validate updated fields
        if 'title' in data:
            if not title or len(title) < 5:
                return web.json_response({"status": "error", "message": "Title too short (min 5 characters)."}, status=400)
            if len(title) > 255:
                return web.json_response({"status": "error", "message": "Title too long (max 255 characters)."}, status=400)
        if 'text' in data:
            if not text or len(text) < 10:
                return web.json_response({"status": "error", "message": "Post text too short (min 10 characters)."}, status=400)

        post['title'] = title
        post['text'] = text
        post['editor_id'] = request.user_id # Update editor
        post['updated_at'] = int(time.time())
        save_db()
        logger.info(f"Post {post_id} updated by user {request.user_id}.")
        return web.json_response({"status": "success", "data": post})
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error updating post:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)


async def delete_post(request):
    """Deletes a blog post."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    post_id = int(request.match_info['id'])
    post = db["posts"].get(post_id)

    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    if post['owner_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only delete your own posts."}, status=403)

    del db["posts"][post_id]
    # Also delete associated comments
    comments_to_delete = [cid for cid, c in db["comments"].items() if c['post_id'] == post_id]
    for cid in comments_to_delete:
        del db["comments"][cid]

    save_db()
    logger.info(f"Post {post_id} deleted.")
    return web.json_response({"status": "success", "message": f"Post {post_id} deleted successfully."})

async def list_comments_for_post(request):
    """Lists all comments for a specific blog post."""
    post_id = int(request.match_info['post_id'])
    if post_id not in db["posts"]:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    comments_for_post = [c for c_id, c in db["comments"].items() if c['post_id'] == post_id]
    # Sort comments by created_at ascending
    sorted_comments = sorted(comments_for_post, key=lambda x: x['created_at'])

    return web.json_response({"status": "success", "data": sorted_comments})

async def create_comment(request):
    """Adds a comment to a specific blog post."""
    global next_comment_id
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    post_id = int(request.match_info['post_id'])
    if post_id not in db["posts"]:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    try:
        data = await request.json()
        text = data.get('text')

        is_valid, error_msg = validate_comment_input(text)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)

        comment_id = next_comment_id
        next_comment_id += 1
        current_time = int(time.time())

        new_comment = {
            "id": comment_id,
            "post_id": post_id,
            "user_id": request.user_id,
            "text": text,
            "created_at": current_time,
            "updated_at": current_time
        }
        db["comments"][comment_id] = new_comment
        save_db()
        logger.info(f"Comment {comment_id} created by user {request.user_id} on post {post_id}.")
        return web.json_response({"status": "success", "data": new_comment}, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error creating comment:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def update_comment(request):
    """Updates an existing comment."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    comment_id = int(request.match_info['comment_id'])
    comment = db["comments"].get(comment_id)

    if not comment:
        return web.json_response({"status": "error", "message": f"Comment with ID {comment_id} not found."}, status=404)

    if comment['user_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only edit your own comments."}, status=403)

    try:
        data = await request.json()
        text = data.get('text', comment['text']) # Use existing if not provided

        # Validate updated text
        if 'text' in data:
            is_valid, error_msg = validate_comment_input(text)
            if not is_valid:
                return web.json_response({"status": "error", "message": error_msg}, status=400)

        comment['text'] = text
        comment['updated_at'] = int(time.time())
        save_db()
        logger.info(f"Comment {comment_id} updated by user {request.user_id}.")
        return web.json_response({"status": "success", "data": comment})
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as e:
        logger.exception("Error updating comment:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def delete_comment(request):
    """Deletes a comment."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authorization header 'Bearer <token>' required."}, status=401)

    comment_id = int(request.match_info['comment_id'])
    comment = db["comments"].get(comment_id)

    if not comment:
        return web.json_response({"status": "error", "message": f"Comment with ID {comment_id} not found."}, status=404)

    if comment['user_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only delete your own comments."}, status=403)

    del db["comments"][comment_id]
    save_db()
    logger.info(f"Comment {comment_id} deleted.")
    return web.json_response({"status": "success", "message": f"Comment {comment_id} deleted successfully."})


# --- Application Setup ---

async def create_app():
    app = web.Application(middlewares=[authenticate_middleware])

    # Routes
    app.router.add_get('/', root_handler)

    # Authentication
    app.router.add_post('/api/v1/register', register_user)
    app.router.add_post('/api/v1/login', login_user)

    # Posts
    app.router.add_post('/api/v1/posts', create_post)
    app.router.add_get('/api/v1/posts', list_posts)
    app.router.add_get('/api/v1/posts/{id}', get_post)
    app.router.add_patch('/api/v1/posts/{id}', update_post)
    app.router.add_delete('/api/v1/posts/{id}', delete_post)

    # Comments
    app.router.add_get('/api/v1/posts/{post_id}/comments', list_comments_for_post)
    app.router.add_post('/api/v1/posts/{post_id}/comments', create_comment)
    app.router.add_patch('/api/v1/comments/{comment_id}', update_comment)
    app.router.add_delete('/api/v1/comments/{comment_id}', delete_comment)

    logger.info("Aiohttp application initialized.")
    return app

def main():
    load_db()
    app = create_app()
    logger.info(f"Starting aiohttp web application on http://{HOST}:{PORT}...")
    web.run_app(app, host=HOST, port=PORT, access_log_format='%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"')

if __name__ == '__main__':
    main()