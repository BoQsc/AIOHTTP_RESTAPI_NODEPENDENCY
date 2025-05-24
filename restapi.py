import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta
import re # For basic regex validation

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
            logger.warning(f"Token signature mismatch for payload: {payload_str}")
            return None # Invalid signature

        user_id_str, expiration_time_str = payload_str.split(':', 1)
        user_id = int(user_id_str)
        expiration_time = int(expiration_time_str)

        if time.time() > expiration_time:
            logger.warning(f"Token for user {user_id} expired.")
            return None # Token expired

        # Check if user actually exists in the database
        # Convert keys to int for lookup as they might be string in JSON
        if str(user_id) not in db["users"] and user_id not in db["users"]:
            logger.warning(f"Token with user_id {user_id} refers to non-existent user.")
            return None

        return user_id
    except (ValueError, TypeError, IndexError) as e:
        logger.error(f"Malformed token decoding failed: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during token decoding: {e}")
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
                logger.debug(f"Invalid or expired token provided.")
        return await handler(request)
    return middleware_handler

def format_timestamp(timestamp):
    """Converts a Unix timestamp to a human-readable string."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp).isoformat()

# --- Data Persistence (Simple JSON) ---

def load_db():
    global db, next_user_id, next_post_id, next_comment_id
    try:
        with open(DATABASE_FILE, 'r') as f:
            loaded_db = json.load(f)
            # Ensure integer keys are restored from string keys
            db["users"] = {int(k): v for k, v in loaded_db.get("users", {}).items()}
            db["posts"] = {int(k): v for k, v in loaded_db.get("posts", {}).items()}
            db["comments"] = {int(k): v for k, v in loaded_db.get("comments", {}).items()}
            
            next_user_id = max(db["users"].keys(), default=0) + 1
            next_post_id = max(db["posts"].keys(), default=0) + 1
            next_comment_id = max(db["comments"].keys(), default=0) + 1
        logger.info("Database loaded from file.")
    except FileNotFoundError:
        logger.info("No existing database file found. Initializing empty database.")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding database file: {e}. Starting with empty database.")
        _reset_db_state()
    except Exception as e:
        logger.error(f"An unexpected error occurred loading database: {e}. Starting with empty database.")
        _reset_db_state()

def _reset_db_state():
    global db, next_user_id, next_post_id, next_comment_id
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
    if not username:
        return False, "Username is required."
    if not password:
        return False, "Password is required."

    username = username.strip()
    password = password.strip()

    if not (3 <= len(username) <= 50):
        return False, "Username must be between 3 and 50 characters."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Username can only contain letters, numbers, underscores, hyphens, and periods."
    
    if not (6 <= len(password) <= 100): # Increased max length for password
        return False, "Password must be between 6 and 100 characters."
    
    # Add simple password complexity (at least one digit, one letter)
    if not (re.search(r"\d", password) and re.search(r"[a-zA-Z]", password)):
        return False, "Password must contain at least one letter and one digit."

    return True, None

def validate_post_input(title, text):
    if not title:
        return False, "Title is required."
    if not text:
        return False, "Text is required."

    title = title.strip()
    text = text.strip()

    if not (5 <= len(title) <= 255):
        return False, "Title must be between 5 and 255 characters."
    if not (10 <= len(text) <= 5000): # Increased max length for text
        return False, "Post text must be between 10 and 5000 characters."
    return True, None

def validate_comment_input(text):
    if not text:
        return False, "Comment text is required."
    
    text = text.strip()

    if not (3 <= len(text) <= 500):
        return False, "Comment text must be between 3 and 500 characters."
    return True, None

# --- API Handlers ---

async def root_handler(request):
    """Handles the root endpoint, providing API info."""
    return web.json_response({
        "message": "Welcome to the Blog API!",
        "version": "v1",
        "description": "A simple blog API for posts and comments.",
        "endpoints": {
            "register": "POST /api/v1/register (username, password)",
            "login": "POST /api/v1/login (username, password)",
            "posts_list": "GET /api/v1/posts?page=<int>&limit=<int>",
            "post_detail": "GET /api/v1/posts/{id}",
            "create_post": "POST /api/v1/posts (title, text) - Auth required",
            "update_post": "PATCH /api/v1/posts/{id} (title, text - partial update) - Auth required, owner only",
            "delete_post": "DELETE /api/v1/posts/{id} - Auth required, owner only",
            "comments_on_post": "GET /api/v1/posts/{post_id}/comments",
            "add_comment": "POST /api/v1/posts/{post_id}/comments (text) - Auth required",
            "update_comment": "PATCH /api/v1/comments/{comment_id} (text) - Auth required, owner only",
            "delete_comment": "DELETE /api/v1/comments/{comment_id} - Auth required, owner only"
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

        # Sanitize and normalize username
        username = username.strip().lower()

        # Check if username already exists (case-insensitive)
        if any(u['username'].lower() == username for u in db["users"].values()):
            return web.json_response({"status": "error", "message": f"Username '{username}' already exists."}, status=409) # 409 Conflict

        user_id = next_user_id
        next_user_id += 1
        password_hash = generate_password_hash(password)
        created_at = int(time.time())

        db["users"][user_id] = {
            "username": username, # Storing normalized username
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
            "username": username,
            "token": token
        }, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
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
            # For login, it's better to return a generic error for security
            return web.json_response({"status": "error", "message": "Invalid username or password."}, status=401)
        
        # Sanitize and normalize username for lookup
        username = username.strip().lower()

        user_found = None
        user_found_id = None
        for user_id, user_data in db["users"].items():
            if user_data['username'].lower() == username: # Case-insensitive comparison
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
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
    except Exception as e:
        logger.exception("Error during user login:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def create_post(request):
    """Creates a new blog post."""
    global next_post_id
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        data = await request.json()
        title = data.get('title')
        text = data.get('text')

        is_valid, error_msg = validate_post_input(title, text)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)
        
        title = title.strip()
        text = text.strip()

        # Optional: Prevent duplicate post titles for the same user
        for post_data in db["posts"].values():
            if post_data['owner_id'] == request.user_id and post_data['title'].lower() == title.lower():
                return web.json_response({"status": "error", "message": "You already have a post with this title."}, status=409)

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
        
        # Prepare response with formatted timestamps
        response_post = new_post.copy()
        response_post['created_at'] = format_timestamp(response_post['created_at'])
        response_post['updated_at'] = format_timestamp(response_post['updated_at'])

        return web.json_response({"status": "success", "data": response_post}, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
    except Exception as e:
        logger.exception("Error creating post:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def list_posts(request):
    """Lists all blog posts."""
    try:
        # Optional pagination
        page = int(request.query.get('page', 1))
        limit = int(request.query.get('limit', 10))

        if page < 1 or limit < 1:
            return web.json_response({"status": "error", "message": "Page and limit must be positive integers."}, status=400)

        all_posts = list(db["posts"].values())
        # Sort posts by updated_at or created_at descending
        sorted_posts = sorted(all_posts, key=lambda x: x.get('updated_at', x['created_at']), reverse=True)
        
        total_posts = len(sorted_posts)
        start_index = (page - 1) * limit
        end_index = start_index + limit
        
        paginated_posts = sorted_posts[start_index:end_index]

        # Format timestamps for response
        formatted_posts = []
        for post in paginated_posts:
            p = post.copy()
            p['created_at'] = format_timestamp(p['created_at'])
            p['updated_at'] = format_timestamp(p['updated_at'])
            formatted_posts.append(p)

        return web.json_response({
            "status": "success",
            "data": formatted_posts,
            "page": page,
            "limit": limit,
            "total_posts": total_posts,
            "total_pages": (total_posts + limit - 1) // limit # Ceiling division
        })
    except ValueError:
        return web.json_response({"status": "error", "message": "Page and limit must be valid integers."}, status=400)
    except Exception as e:
        logger.exception("Error listing posts:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def get_post(request):
    """Retrieves a single blog post by ID."""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid post ID format."}, status=400)

    post = db["posts"].get(post_id)
    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)
    
    # Format timestamps for response
    response_post = post.copy()
    response_post['created_at'] = format_timestamp(response_post['created_at'])
    response_post['updated_at'] = format_timestamp(response_post['updated_at'])

    return web.json_response({"status": "success", "data": response_post})

async def update_post(request):
    """Updates an existing blog post."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid post ID format."}, status=400)

    post = db["posts"].get(post_id)

    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    if post['owner_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only edit your own posts."}, status=403)

    try:
        data = await request.json()
        
        # Only update if the field is explicitly provided in the request body
        updated_title = data.get('title')
        updated_text = data.get('text')
        
        changes_made = False

        if updated_title is not None:
            updated_title = updated_title.strip()
            if not updated_title: # Check if title is empty after strip
                 return web.json_response({"status": "error", "message": "Title cannot be empty."}, status=400)
            if not (5 <= len(updated_title) <= 255):
                return web.json_response({"status": "error", "message": "Title must be between 5 and 255 characters."}, status=400)
            if post['title'] != updated_title:
                post['title'] = updated_title
                changes_made = True

        if updated_text is not None:
            updated_text = updated_text.strip()
            if not updated_text: # Check if text is empty after strip
                 return web.json_response({"status": "error", "message": "Text cannot be empty."}, status=400)
            if not (10 <= len(updated_text) <= 5000):
                return web.json_response({"status": "error", "message": "Post text must be between 10 and 5000 characters."}, status=400)
            if post['text'] != updated_text:
                post['text'] = updated_text
                changes_made = True

        if changes_made:
            post['editor_id'] = request.user_id # Update editor
            post['updated_at'] = int(time.time())
            save_db()
            logger.info(f"Post {post_id} updated by user {request.user_id}.")
        else:
            logger.info(f"Post {post_id} update request by user {request.user_id} - no changes detected.")
            # Return 200 OK but with a message indicating no change if preferred
            return web.json_response({"status": "success", "message": "No changes to apply.", "data": post})

        # Prepare response with formatted timestamps
        response_post = post.copy()
        response_post['created_at'] = format_timestamp(response_post['created_at'])
        response_post['updated_at'] = format_timestamp(response_post['updated_at'])

        return web.json_response({"status": "success", "data": response_post})
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
    except Exception as e:
        logger.exception("Error updating post:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)


async def delete_post(request):
    """Deletes a blog post."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid post ID format."}, status=400)

    post = db["posts"].get(post_id)

    if not post:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    if post['owner_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only delete your own posts."}, status=403)

    del db["posts"][post_id]
    # Also delete associated comments
    comments_to_delete = [cid for cid, c in list(db["comments"].items()) if c['post_id'] == post_id]
    for cid in comments_to_delete:
        del db["comments"][cid]

    save_db()
    logger.info(f"Post {post_id} and its {len(comments_to_delete)} associated comments deleted by user {request.user_id}.")
    return web.json_response({"status": "success", "message": f"Post {post_id} and associated comments deleted successfully."})

async def list_comments_for_post(request):
    """Lists all comments for a specific blog post."""
    try:
        post_id = int(request.match_info['post_id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid post ID format."}, status=400)

    if post_id not in db["posts"]:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    comments_for_post = [c for c_id, c in db["comments"].items() if c['post_id'] == post_id]
    # Sort comments by created_at ascending
    sorted_comments = sorted(comments_for_post, key=lambda x: x['created_at'])

    # Format timestamps for response
    formatted_comments = []
    for comment in sorted_comments:
        c = comment.copy()
        c['created_at'] = format_timestamp(c['created_at'])
        c['updated_at'] = format_timestamp(c['updated_at'])
        formatted_comments.append(c)

    return web.json_response({"status": "success", "data": formatted_comments})

async def create_comment(request):
    """Adds a comment to a specific blog post."""
    global next_comment_id
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        post_id = int(request.match_info['post_id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid post ID format."}, status=400)

    if post_id not in db["posts"]:
        return web.json_response({"status": "error", "message": f"Post with ID {post_id} not found."}, status=404)

    try:
        data = await request.json()
        text = data.get('text')

        is_valid, error_msg = validate_comment_input(text)
        if not is_valid:
            return web.json_response({"status": "error", "message": error_msg}, status=400)
        
        text = text.strip()

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
        
        # Prepare response with formatted timestamps
        response_comment = new_comment.copy()
        response_comment['created_at'] = format_timestamp(response_comment['created_at'])
        response_comment['updated_at'] = format_timestamp(response_comment['updated_at'])

        return web.json_response({"status": "success", "data": response_comment}, status=201)
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
    except Exception as e:
        logger.exception("Error creating comment:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def update_comment(request):
    """Updates an existing comment."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        comment_id = int(request.match_info['comment_id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid comment ID format."}, status=400)

    comment = db["comments"].get(comment_id)

    if not comment:
        return web.json_response({"status": "error", "message": f"Comment with ID {comment_id} not found."}, status=404)

    if comment['user_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only edit your own comments."}, status=403)

    try:
        data = await request.json()
        updated_text = data.get('text')
        
        changes_made = False

        if updated_text is not None:
            updated_text = updated_text.strip()
            is_valid, error_msg = validate_comment_input(updated_text)
            if not is_valid:
                return web.json_response({"status": "error", "message": error_msg}, status=400)
            if comment['text'] != updated_text:
                comment['text'] = updated_text
                changes_made = True
        
        if changes_made:
            comment['updated_at'] = int(time.time())
            save_db()
            logger.info(f"Comment {comment_id} updated by user {request.user_id}.")
        else:
            logger.info(f"Comment {comment_id} update request by user {request.user_id} - no changes detected.")
            return web.json_response({"status": "success", "message": "No changes to apply.", "data": comment})

        # Prepare response with formatted timestamps
        response_comment = comment.copy()
        response_comment['created_at'] = format_timestamp(response_comment['created_at'])
        response_comment['updated_at'] = format_timestamp(response_comment['updated_at'])

        return web.json_response({"status": "success", "data": response_comment})
    except json.JSONDecodeError:
        return web.json_response({"status": "error", "message": "Invalid JSON format in request body."}, status=400)
    except Exception as e:
        logger.exception("Error updating comment:")
        return web.json_response({"status": "error", "message": f"Internal server error: {e}"}, status=500)

async def delete_comment(request):
    """Deletes a comment."""
    if not request.user_id:
        return web.json_response({"status": "error", "message": "Authentication required."}, status=401)

    try:
        comment_id = int(request.match_info['comment_id'])
    except ValueError:
        return web.json_response({"status": "error", "message": "Invalid comment ID format."}, status=400)

    comment = db["comments"].get(comment_id)

    if not comment:
        return web.json_response({"status": "error", "message": f"Comment with ID {comment_id} not found."}, status=404)

    if comment['user_id'] != request.user_id:
        return web.json_response({"status": "error", "message": "You can only delete your own comments."}, status=403)

    del db["comments"][comment_id]
    save_db()
    logger.info(f"Comment {comment_id} deleted by user {request.user_id}.")
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

    # Register cleanup hook to save DB on shutdown
    app.on_shutdown.append(shutdown_app)

    logger.info("Aiohttp application initialized.")
    return app

async def shutdown_app(app):
    """Called when the application is shutting down."""
    logger.info("Aiohttp application shutting down. Saving database...")
    save_db()

def main():
    load_db()
    app = create_app() # This returns a future, not the app object itself in this context
    logger.info(f"Starting aiohttp web application on http://{HOST}:{PORT}...")
    web.run_app(app, host=HOST, port=PORT, access_log_format='%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"')

if __name__ == '__main__':
    main()