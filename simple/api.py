"""
Main server file - Clean HTTP handlers only
All database logic is in db.py
"""

from aiohttp import web
import ssl
import logging
import uuid
from pathlib import Path

# Import all database functions
import tools.db as db

# File upload directory
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ========================================
# YOUR EXISTING HANDLERS (UNCHANGED)
# ========================================

async def index(request):
    return web.Response(text="Hello world")
    
async def index_post(request):
    return web.json_response(
        {"message": f"Hello {await request.json()} index", 
        "status": "success"}
    )
    
async def api(request):
    return web.json_response(
        {"message": "Hello", 
        "status": "success"}
    )

# ========================================
# AUTHENTICATION HANDLERS (CLEAN)
# ========================================

async def register_user(request):
    """Register new user"""
    data = await request.json()
    
    # Check if user already exists
    existing = await db.get_user_by_email(data["email"])
    if existing:
        return web.json_response(
            {"message": "User already exists", "status": "error"}, 
            status=400
        )
    
    # Create user
    user_id = await db.create_user(
        data["username"], 
        data["email"], 
        data["password"]
    )
    
    return web.json_response({
        "message": "User registered successfully",
        "user_id": user_id,
        "status": "success"
    })

async def login_user(request):
    """User login"""
    data = await request.json()
    
    # Authenticate user
    user = await db.authenticate_user(data["email"], data["password"])
    if not user:
        return web.json_response(
            {"message": "Invalid credentials", "status": "error"}, 
            status=401
        )
    
    # Create session
    token = await db.create_session(user["id"])
    
    return web.json_response({
        "message": "Login successful",
        "token": token,
        "user": user,
        "status": "success"
    })

async def logout_user(request):
    """User logout"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    if await db.delete_session(token):
        return web.json_response({"message": "Logged out successfully", "status": "success"})
    else:
        return web.json_response({"message": "Invalid session", "status": "error"}, status=400)

async def get_current_user(request):
    """Get current user info"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    session = await db.get_session(token)
    if not session:
        return web.json_response({"message": "Invalid session", "status": "error"}, status=401)
    
    return web.json_response({
        "user": {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email"],
            "role": session["role"]
        },
        "status": "success"
    })

# ========================================
# BLOG POST HANDLERS (CLEAN)
# ========================================

async def create_post(request):
    """Create new blog post"""
    data = await request.json()
    
    post_id = await db.create_post(
        data["author_id"],
        data["title"],
        data["content"],
        data.get("status", "draft"),
        data.get("tags", "")
    )
    
    return web.json_response({
        "message": "Post created successfully",
        "post_id": post_id,
        "status": "success"
    })

async def get_post(request):
    """Get single post"""
    post_id = request.match_info['id']
    
    post = await db.get_post_by_id(post_id)
    if not post:
        return web.json_response(
            {"message": "Post not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "data": post,
        "status": "success"
    })

async def get_published_posts(request):
    """Get published posts"""
    limit = int(request.query.get('limit', 20))
    offset = int(request.query.get('offset', 0))
    
    posts = await db.get_published_posts(limit, offset)
    
    return web.json_response({
        "data": posts,
        "count": len(posts),
        "status": "success"
    })

async def get_user_posts(request):
    """Get posts by user"""
    user_id = request.match_info['user_id']
    status = request.query.get('status')
    
    posts = await db.get_posts_by_author(user_id, status)
    
    return web.json_response({
        "data": posts,
        "count": len(posts),
        "status": "success"
    })

async def update_post(request):
    """Update post"""
    post_id = request.match_info['id']
    data = await request.json()
    
    updated = await db.update_post(post_id, **data)
    if not updated:
        return web.json_response(
            {"message": "Post not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "message": "Post updated successfully",
        "status": "success"
    })

async def delete_post(request):
    """Delete post"""
    post_id = request.match_info['id']
    
    deleted = await db.delete_post(post_id)
    if not deleted:
        return web.json_response(
            {"message": "Post not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "message": "Post deleted successfully",
        "status": "success"
    })

async def search_posts(request):
    """Search posts"""
    query = request.query.get('q', '')
    if not query:
        return web.json_response(
            {"message": "Search query required", "status": "error"}, 
            status=400
        )
    
    results = await db.search_posts(query)
    
    return web.json_response({
        "data": results,
        "count": len(results),
        "query": query,
        "status": "success"
    })

# ========================================
# COMMENT HANDLERS (CLEAN)
# ========================================

async def add_comment(request):
    """Add comment to post"""
    data = await request.json()
    post_id = request.match_info['post_id']
    
    comment_id = await db.create_comment(
        post_id,
        data["author_id"],
        data["content"]
    )
    
    return web.json_response({
        "message": "Comment added successfully",
        "comment_id": comment_id,
        "status": "success"
    })

async def get_post_comments(request):
    """Get comments for post"""
    post_id = request.match_info['post_id']
    
    comments = await db.get_post_comments(post_id)
    
    return web.json_response({
        "data": comments,
        "count": len(comments),
        "status": "success"
    })

async def update_comment(request):
    """Update comment"""
    comment_id = request.match_info['id']
    data = await request.json()
    
    updated = await db.update_comment(comment_id, data["content"])
    if not updated:
        return web.json_response(
            {"message": "Comment not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "message": "Comment updated successfully",
        "status": "success"
    })

async def delete_comment(request):
    """Delete comment"""
    comment_id = request.match_info['id']
    
    deleted = await db.delete_comment(comment_id)
    if not deleted:
        return web.json_response(
            {"message": "Comment not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "message": "Comment deleted successfully",
        "status": "success"
    })

# ========================================
# FILE UPLOAD HANDLERS (CLEAN)
# ========================================

async def upload_file(request):
    """Upload file"""
    reader = await request.multipart()
    uploader_id = request.headers.get("user-id", "anonymous")
    
    async for field in reader:
        if field.name == 'file':
            # Generate unique filename
            file_id = str(uuid.uuid4())
            original_name = field.filename or "unknown"
            file_ext = Path(original_name).suffix
            safe_filename = f"{file_id}{file_ext}"
            file_path = UPLOAD_DIR / safe_filename
            
            # Save file to disk
            size = 0
            with open(file_path, 'wb') as f:
                async for chunk in field:
                    f.write(chunk)
                    size += len(chunk)
            
            # Save metadata to database
            file_record_id = await db.create_file(
                uploader_id,
                original_name,
                str(file_path),
                size,
                field.content_type
            )
            
            return web.json_response({
                "message": "File uploaded successfully",
                "file_id": file_record_id,
                "name": original_name,
                "size": size,
                "status": "success"
            })
    
    return web.json_response(
        {"message": "No file provided", "status": "error"}, 
        status=400
    )

async def get_file_info(request):
    """Get file metadata"""
    file_id = request.match_info['id']
    
    file_info = await db.get_file_by_id(file_id)
    if not file_info:
        return web.json_response(
            {"message": "File not found", "status": "error"}, 
            status=404
        )
    
    return web.json_response({
        "data": file_info,
        "status": "success"
    })

async def download_file(request):
    """Download file"""
    file_id = request.match_info['id']
    
    file_info = await db.get_file_by_id(file_id)
    if not file_info or not Path(file_info["path"]).exists():
        return web.json_response(
            {"message": "File not found", "status": "error"}, 
            status=404
        )
    
    return web.FileResponse(
        file_info["path"],
        headers={
            "Content-Disposition": f'attachment; filename="{file_info["name"]}"'
        }
    )

async def get_user_files(request):
    """Get files uploaded by user"""
    user_id = request.match_info['user_id']
    
    files = await db.get_user_files(user_id)
    
    return web.json_response({
        "data": files,
        "count": len(files),
        "status": "success"
    })

async def delete_file(request):
    """Delete file"""
    file_id = request.match_info['id']
    
    # Get file info to delete from disk
    file_info = await db.get_file_by_id(file_id)
    if not file_info:
        return web.json_response(
            {"message": "File not found", "status": "error"}, 
            status=404
        )
    
    # Delete file from disk
    file_path = Path(file_info["path"])
    if file_path.exists():
        file_path.unlink()
    
    # Delete from database
    await db.delete_file(file_id)
    
    return web.json_response({
        "message": "File deleted successfully",
        "status": "success"
    })

# ========================================
# ADMIN HANDLERS (CLEAN)
# ========================================

async def get_dashboard_stats(request):
    """Get admin dashboard statistics"""
    stats = await db.get_database_stats()
    
    return web.json_response({
        "data": stats,
        "status": "success"
    })

async def get_all_users(request):
    """Get all users (admin only)"""
    users = await db.get_all_users()
    
    return web.json_response({
        "data": users,
        "count": len(users),
        "status": "success"
    })

async def get_user_activity(request):
    """Get user activity stats"""
    user_id = request.match_info['user_id']
    
    activity = await db.get_user_activity(user_id)
    
    return web.json_response({
        "data": activity,
        "status": "success"
    })

# ========================================
# MIDDLEWARE
# ========================================

@web.middleware 
async def cors_handler(request, handler):
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

async def cleanup_sessions_middleware(request, handler):
    """Cleanup expired sessions periodically"""
    # Clean up expired sessions on each request (could be optimized)
    await db.cleanup_expired_sessions()
    return await handler(request)

# ========================================
# APPLICATION SETUP
# ========================================

async def init_app(app):
    """Initialize database on startup"""
    await db.init_database()
    logging.info("Database initialized successfully")

async def cleanup_app(app):
    """Cleanup on shutdown"""
    logging.info("Server shutting down")

# Create application
app = web.Application()

# Add middleware
app.middlewares.append(cors_handler)
app.middlewares.append(cleanup_sessions_middleware)

# Your existing routes
app.router.add_get('/', index)
app.router.add_post('/', index_post)
app.router.add_get('/api', api)

# Authentication routes
app.router.add_post('/auth/register', register_user)
app.router.add_post('/auth/login', login_user)
app.router.add_post('/auth/logout', logout_user)
app.router.add_get('/auth/me', get_current_user)

# Blog post routes
app.router.add_post('/posts', create_post)
app.router.add_get('/posts', get_published_posts)
app.router.add_get('/posts/{id}', get_post)
app.router.add_put('/posts/{id}', update_post)
app.router.add_delete('/posts/{id}', delete_post)
app.router.add_get('/users/{user_id}/posts', get_user_posts)
app.router.add_get('/search/posts', search_posts)

# Comment routes
app.router.add_post('/posts/{post_id}/comments', add_comment)
app.router.add_get('/posts/{post_id}/comments', get_post_comments)
app.router.add_put('/comments/{id}', update_comment)
app.router.add_delete('/comments/{id}', delete_comment)

# File routes
app.router.add_post('/upload', upload_file)
app.router.add_get('/files/{id}', get_file_info)
app.router.add_get('/files/{id}/download', download_file)
app.router.add_get('/users/{user_id}/files', get_user_files)
app.router.add_delete('/files/{id}', delete_file)

# Admin routes
app.router.add_get('/admin/stats', get_dashboard_stats)
app.router.add_get('/admin/users', get_all_users)
app.router.add_get('/admin/users/{user_id}/activity', get_user_activity)

# Lifecycle events
app.on_startup.append(init_app)
app.on_cleanup.append(cleanup_app)

# SSL setup (your existing configuration)
logging.basicConfig(level=logging.INFO)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')

if __name__ == '__main__':
    web.run_app(
        app, 
        ssl_context=ctx, 
        port=443, 
        access_log=logging.getLogger('aiohttp.access')
    )

"""
USAGE EXAMPLES:

# Register user
curl -X POST -H "Content-Type: application/json" \
     -d '{"username": "john", "email": "john@example.com", "password": "secret"}' \
     https://localhost/auth/register

# Login
curl -X POST -H "Content-Type: application/json" \
     -d '{"email": "john@example.com", "password": "secret"}' \
     https://localhost/auth/login

# Create post
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" \
     -d '{"title": "My Post", "content": "Hello world", "author_id": "USER_ID"}' \
     https://localhost/posts

# Upload file
curl -X POST -F "file=@document.pdf" -H "user-id: USER_ID" \
     https://localhost/upload

# Search posts
curl https://localhost/search/posts?q=python

# Get stats
curl https://localhost/admin/stats
"""