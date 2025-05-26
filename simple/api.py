"""
Enhanced API server with security, validation, and proper structure
"""

from aiohttp import web
import ssl
import logging
import uuid
import json
import secrets
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional
import re
from functools import wraps

# Import all database functions
import tools.db as db

# Configuration
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# File upload limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt', '.zip'}
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif',
    'application/pdf', 'text/plain',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/zip'
}

# Validation patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')

# ========================================
# VALIDATION HELPERS
# ========================================

class ValidationError(Exception):
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(message)

def validate_email(email: str) -> str:
    """Validate and sanitize email"""
    if not email or not isinstance(email, str):
        raise ValidationError("Email is required", "email")
    
    email = email.strip().lower()
    if not EMAIL_PATTERN.match(email):
        raise ValidationError("Invalid email format", "email")
    
    if len(email) > 255:
        raise ValidationError("Email too long", "email")
    
    return email

def validate_username(username: str) -> str:
    """Validate and sanitize username"""
    if not username or not isinstance(username, str):
        raise ValidationError("Username is required", "username")
    
    username = username.strip()
    if not USERNAME_PATTERN.match(username):
        raise ValidationError("Username must be 3-20 characters, letters/numbers/underscore only", "username")
    
    return username

def validate_password(password: str) -> str:
    """Validate password"""
    if not password or not isinstance(password, str):
        raise ValidationError("Password is required", "password")
    
    if len(password) < 6:
        raise ValidationError("Password must be at least 6 characters", "password")
    
    if len(password) > 128:
        raise ValidationError("Password too long", "password")
    
    return password

def validate_string(value: str, field_name: str, min_len: int = 1, max_len: int = 1000) -> str:
    """Validate and sanitize string field"""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", field_name)
    
    value = value.strip()
    if len(value) < min_len:
        raise ValidationError(f"{field_name} is too short (min {min_len} chars)", field_name)
    
    if len(value) > max_len:
        raise ValidationError(f"{field_name} is too long (max {max_len} chars)", field_name)
    
    return value

def validate_uuid(value: str, field_name: str) -> str:
    """Validate UUID format"""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", field_name)
    
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        raise ValidationError(f"Invalid {field_name} format", field_name)

def validate_file_upload(field) -> Dict[str, Any]:
    """Validate uploaded file"""
    if not field.filename:
        raise ValidationError("No filename provided", "file")
    
    # Check file extension
    file_ext = Path(field.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "file")
    
    # Check MIME type
    mime_type = field.content_type
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValidationError(f"MIME type not allowed: {mime_type}", "file")
    
    return {
        'filename': field.filename,
        'extension': file_ext,
        'mime_type': mime_type
    }

# ========================================
# PAGINATION HELPERS
# ========================================

def get_pagination_params(request) -> Dict[str, int]:
    """Extract and validate pagination parameters"""
    try:
        limit = int(request.query.get('limit', 20))
        offset = int(request.query.get('offset', 0))
        
        # Enforce reasonable limits
        limit = max(1, min(limit, 100))  # Between 1 and 100
        offset = max(0, offset)  # Non-negative
        
        return {'limit': limit, 'offset': offset}
    except ValueError:
        raise ValidationError("Invalid pagination parameters")

def create_paginated_response(data: List[Dict], total_count: int, limit: int, offset: int) -> Dict:
    """Create standardized paginated response"""
    return {
        "data": data,
        "pagination": {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total_count
        },
        "status": "success"
    }

# ========================================
# CSRF PROTECTION
# ========================================

# In-memory CSRF token storage (use Redis in production)
csrf_tokens = {}

def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return secrets.token_urlsafe(32)

async def get_csrf_token(request):
    """Get CSRF token endpoint"""
    token = generate_csrf_token()
    # In production, associate with session
    csrf_tokens[token] = True
    
    return web.json_response({
        "csrf_token": token,
        "status": "success"
    })

def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token"""
    return token in csrf_tokens

@web.middleware
async def csrf_protection(request, handler):
    """CSRF protection middleware"""
    # Skip CSRF for GET, HEAD, OPTIONS
    if request.method in ['GET', 'HEAD', 'OPTIONS']:
        return await handler(request)
    
    # Skip CSRF for auth endpoints (handle separately)
    if request.path.startswith('/api/v1/auth/'):
        return await handler(request)
    
    # Check CSRF token
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or not validate_csrf_token(csrf_token):
        return web.json_response(
            {"message": "CSRF token missing or invalid", "status": "error"}, 
            status=403
        )
    
    return await handler(request)

# ========================================
# AUTHENTICATION MIDDLEWARE
# ========================================

@web.middleware
async def auth_middleware(request, handler):
    """Authentication middleware"""
    # Public endpoints that don't require auth
    public_paths = [
        '/api/v1/auth/register',
        '/api/v1/auth/login',
        '/api/v1/posts',  # GET only
        '/api/v1/posts/',
        '/api/v1/csrf-token',
        '/api/v1/search/posts'
    ]
    
    # Check if path requires authentication
    path = request.path
    method = request.method
    
    # Allow GET requests to posts endpoints without auth
    if method == 'GET' and any(path.startswith(p) for p in public_paths):
        return await handler(request)
    
    # Skip auth for public paths
    if path in public_paths:
        return await handler(request)
    
    # Extract and validate token
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return web.json_response(
            {"message": "Authentication required", "status": "error"}, 
            status=401
        )
    
    token = auth_header.replace("Bearer ", "")
    session = await db.get_session(token)
    
    if not session:
        return web.json_response(
            {"message": "Invalid or expired session", "status": "error"}, 
            status=401
        )
    
    # Add user info to request
    request['user'] = session
    return await handler(request)

# ========================================
# ERROR HANDLING
# ========================================

@web.middleware
async def error_handling_middleware(request, handler):
    """Global error handling"""
    try:
        return await handler(request)
    except ValidationError as e:
        return web.json_response({
            "message": e.message,
            "field": e.field,
            "status": "error"
        }, status=400)
    except Exception as e:
        logging.error(f"Unhandled error: {e}")
        return web.json_response({
            "message": "Internal server error",
            "status": "error"
        }, status=500)

# ========================================
# YOUR EXISTING HANDLERS (UPDATED)
# ========================================

async def index(request):
    return web.Response(text="API v1 - Hello world")

# ========================================
# AUTHENTICATION HANDLERS (ENHANCED)
# ========================================

async def register_user(request):
    """Register new user with validation"""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    # Validate input
    username = validate_username(data.get("username"))
    email = validate_email(data.get("email"))
    password = validate_password(data.get("password"))
    
    # Check if user already exists
    existing = await db.get_user_by_email(email)
    if existing:
        raise ValidationError("User with this email already exists", "email")
    
    existing_username = await db.get_user_by_username(username)
    if existing_username:
        raise ValidationError("Username already taken", "username")
    
    # Create user
    user_id = await db.create_user(username, email, password)
    
    return web.json_response({
        "message": "User registered successfully",
        "user_id": user_id,
        "status": "success"
    })

async def login_user(request):
    """User login with validation"""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    email = validate_email(data.get("email"))
    password = validate_password(data.get("password"))
    
    # Authenticate user
    user = await db.authenticate_user(email, password)
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
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Not authenticated", "status": "error"}, status=401)
    
    # Get token from request (already validated by middleware)
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    if await db.delete_session(token):
        return web.json_response({"message": "Logged out successfully", "status": "success"})
    else:
        return web.json_response({"message": "Logout failed", "status": "error"}, status=400)

async def get_current_user(request):
    """Get current user info"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Not authenticated", "status": "error"}, status=401)
    
    return web.json_response({
        "user": {
            "id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        },
        "status": "success"
    })

# ========================================
# BLOG POST HANDLERS (ENHANCED)
# ========================================

async def create_post(request):
    """Create new blog post with validation"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    # Validate input
    title = validate_string(data.get("title"), "title", min_len=1, max_len=200)
    content = validate_string(data.get("content"), "content", min_len=1, max_len=50000)
    status = data.get("status", "draft")
    tags = data.get("tags", "")
    
    if status not in ["draft", "published"]:
        raise ValidationError("Status must be 'draft' or 'published'", "status")
    
    if tags and len(tags) > 500:
        raise ValidationError("Tags too long (max 500 chars)", "tags")
    
    post_id = await db.create_post(
        user["user_id"],
        title,
        content,
        status,
        tags
    )
    
    return web.json_response({
        "message": "Post created successfully",
        "post_id": post_id,
        "status": "success"
    })

async def get_post(request):
    """Get single post"""
    post_id = validate_uuid(request.match_info['id'], "post_id")
    
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
    """Get published posts with pagination"""
    pagination = get_pagination_params(request)
    
    posts, total_count = await db.get_published_posts_paginated(
        pagination['limit'], 
        pagination['offset']
    )
    
    return web.json_response(
        create_paginated_response(posts, total_count, pagination['limit'], pagination['offset'])
    )

async def get_user_posts(request):
    """Get posts by user with pagination"""
    user_id = validate_uuid(request.match_info['user_id'], "user_id")
    status = request.query.get('status')
    pagination = get_pagination_params(request)
    
    if status and status not in ["draft", "published"]:
        raise ValidationError("Invalid status filter", "status")
    
    posts = await db.get_posts_by_author(user_id, status)
    
    # Apply pagination
    start = pagination['offset']
    end = start + pagination['limit']
    paginated_posts = posts[start:end]
    
    return web.json_response(
        create_paginated_response(paginated_posts, len(posts), pagination['limit'], pagination['offset'])
    )

async def update_post(request):
    """Update post with validation"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    post_id = validate_uuid(request.match_info['id'], "post_id")
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    # Validate fields if provided
    update_data = {}
    if 'title' in data:
        update_data['title'] = validate_string(data['title'], "title", min_len=1, max_len=200)
    if 'content' in data:
        update_data['content'] = validate_string(data['content'], "content", min_len=1, max_len=50000)
    if 'status' in data:
        if data['status'] not in ["draft", "published"]:
            raise ValidationError("Status must be 'draft' or 'published'", "status")
        update_data['status'] = data['status']
    if 'tags' in data:
        if len(data['tags']) > 500:
            raise ValidationError("Tags too long (max 500 chars)", "tags")
        update_data['tags'] = data['tags']
    
    if not update_data:
        raise ValidationError("No valid fields to update")
    
    updated = await db.update_post(post_id, **update_data)
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
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    post_id = validate_uuid(request.match_info['id'], "post_id")
    
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
    """Search posts with pagination"""
    query = request.query.get('q', '').strip()
    if not query:
        raise ValidationError("Search query required", "q")
    
    if len(query) > 100:
        raise ValidationError("Search query too long", "q")
    
    pagination = get_pagination_params(request)
    
    results = await db.search_posts(query, pagination['limit'])
    
    return web.json_response({
        "data": results,
        "count": len(results),
        "query": query,
        "status": "success"
    })

# ========================================
# COMMENT HANDLERS (ENHANCED)
# ========================================

async def add_comment(request):
    """Add comment to post with validation"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    post_id = validate_uuid(request.match_info['post_id'], "post_id")
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    content = validate_string(data.get("content"), "content", min_len=1, max_len=2000)
    
    comment_id = await db.create_comment(
        post_id,
        user["user_id"],
        content
    )
    
    return web.json_response({
        "message": "Comment added successfully",
        "comment_id": comment_id,
        "status": "success"
    })

async def get_post_comments(request):
    """Get comments for post with pagination"""
    post_id = validate_uuid(request.match_info['post_id'], "post_id")
    
    comments = await db.get_post_comments(post_id)
    
    return web.json_response({
        "data": comments,
        "count": len(comments),
        "status": "success"
    })

async def update_comment(request):
    """Update comment with validation"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    comment_id = validate_uuid(request.match_info['id'], "comment_id")
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    content = validate_string(data.get("content"), "content", min_len=1, max_len=2000)
    
    updated = await db.update_comment(comment_id, content)
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
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    comment_id = validate_uuid(request.match_info['id'], "comment_id")
    
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
# FILE UPLOAD HANDLERS (ENHANCED)
# ========================================

async def upload_file(request):
    """Upload file with validation"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    reader = await request.multipart()
    
    async for field in reader:
        if field.name == 'file':
            # Validate file
            file_info = validate_file_upload(field)
            
            # Generate unique filename
            file_id = str(uuid.uuid4())
            file_ext = file_info['extension']
            safe_filename = f"{file_id}{file_ext}"
            file_path = UPLOAD_DIR / safe_filename
            
            # Save file to disk with size checking
            size = 0
            with open(file_path, 'wb') as f:
                async for chunk in field:
                    size += len(chunk)
                    if size > MAX_FILE_SIZE:
                        # Clean up partial file
                        f.close()
                        file_path.unlink()
                        raise ValidationError(f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)", "file")
                    f.write(chunk)
            
            # Save metadata to database
            file_record_id = await db.create_file(
                user["user_id"],
                file_info['filename'],
                str(file_path),
                size,
                file_info['mime_type']
            )
            
            return web.json_response({
                "message": "File uploaded successfully",
                "file_id": file_record_id,
                "name": file_info['filename'],
                "size": size,
                "status": "success"
            })
    
    raise ValidationError("No file provided", "file")

async def get_file_info(request):
    """Get file metadata"""
    file_id = validate_uuid(request.match_info['id'], "file_id")
    
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
    file_id = validate_uuid(request.match_info['id'], "file_id")
    
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
    """Get files uploaded by user with pagination"""
    user_id = validate_uuid(request.match_info['user_id'], "user_id")
    pagination = get_pagination_params(request)
    
    files = await db.get_user_files(user_id)
    
    # Apply pagination
    start = pagination['offset']
    end = start + pagination['limit']
    paginated_files = files[start:end]
    
    return web.json_response(
        create_paginated_response(paginated_files, len(files), pagination['limit'], pagination['offset'])
    )

async def delete_file(request):
    """Delete file"""
    user = request.get('user')
    if not user:
        return web.json_response({"message": "Authentication required", "status": "error"}, status=401)
    
    file_id = validate_uuid(request.match_info['id'], "file_id")
    
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
# ADMIN HANDLERS (ENHANCED)
# ========================================

async def get_dashboard_stats(request):
    """Get admin dashboard statistics"""
    user = request.get('user')
    if not user or user.get('role') != 'admin':
        return web.json_response({"message": "Admin access required", "status": "error"}, status=403)
    
    stats = await db.get_database_stats()
    
    return web.json_response({
        "data": stats,
        "status": "success"
    })

async def get_all_users(request):
    """Get all users (admin only) with pagination"""
    user = request.get('user')
    if not user or user.get('role') != 'admin':
        return web.json_response({"message": "Admin access required", "status": "error"}, status=403)
    
    pagination = get_pagination_params(request)
    
    users, total_count = await db.get_all_users_paginated(pagination['limit'], pagination['offset'])
    
    return web.json_response(
        create_paginated_response(users, total_count, pagination['limit'], pagination['offset'])
    )

async def get_user_activity(request):
    """Get user activity stats"""
    user = request.get('user')
    if not user or user.get('role') != 'admin':
        return web.json_response({"message": "Admin access required", "status": "error"}, status=403)
    
    user_id = validate_uuid(request.match_info['user_id'], "user_id")
    
    activity = await db.get_user_activity(user_id)
    
    return web.json_response({
        "data": activity,
        "status": "success"
    })

# ========================================
# CORS MIDDLEWARE
# ========================================

@web.middleware 
async def cors_handler(request, handler):
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token'
    return response

async def cleanup_sessions_middleware(request, handler):
    """Cleanup expired sessions periodically"""
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

# Add middleware (order matters!)
app.middlewares.append(cors_handler)
app.middlewares.append(error_handling_middleware)
app.middlewares.append(csrf_protection)
app.middlewares.append(auth_middleware)
app.middlewares.append(cleanup_sessions_middleware)

# API v1 routes
app.router.add_get('/api/v1/', index)
app.router.add_get('/api/v1/csrf-token', get_csrf_token)

# Authentication routes
app.router.add_post('/api/v1/auth/register', register_user)
app.router.add_post('/api/v1/auth/login', login_user)
app.router.add_post('/api/v1/auth/logout', logout_user)
app.router.add_get('/api/v1/auth/me', get_current_user)

# Blog post routes
app.router.add_post('/api/v1/posts', create_post)
app.router.add_get('/api/v1/posts', get_published_posts)
app.router.add_get('/api/v1/posts/{id}', get_post)
app.router.add_put('/api/v1/posts/{id}', update_post)
app.router.add_delete('/api/v1/posts/{id}', delete_post)
app.router.add_get('/api/v1/users/{user_id}/posts', get_user_posts)
app.router.add_get('/api/v1/search/posts', search_posts)

# Comment routes
app.router.add_post('/api/v1/posts/{post_id}/comments', add_comment)
app.router.add_get('/api/v1/posts/{post_id}/comments', get_post_comments)
app.router.add_put('/api/v1/comments/{id}', update_comment)
app.router.add_delete('/api/v1/comments/{id}', delete_comment)

# File routes
app.router.add_post('/api/v1/upload', upload_file)
app.router.add_get('/api/v1/files/{id}', get_file_info)
app.router.add_get('/api/v1/files/{id}/download', download_file)
app.router.add_get('/api/v1/users/{user_id}/files', get_user_files)
app.router.add_delete('/api/v1/files/{id}', delete_file)

# Admin routes
app.router.add_get('/api/v1/admin/stats', get_dashboard_stats)
app.router.add_get('/api/v1/admin/users', get_all_users)
app.router.add_get('/api/v1/admin/users/{user_id}/activity', get_user_activity)

# Lifecycle events
app.on_startup.append(init_app)
app.on_cleanup.append(cleanup_app)

# SSL setup
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
USAGE EXAMPLES WITH API v1:

# Get CSRF token first
curl https://localhost/api/v1/csrf-token

# Register user
curl -X POST -H "Content-Type: application/json" -H "X-CSRF-Token: TOKEN" \
     -d '{"username": "john", "email": "john@example.com", "password": "secret123"}' \
     https://localhost/api/v1/auth/register

# Login
curl -X POST -H "Content-Type: application/json" -H "X-CSRF-Token: TOKEN" \
     -d '{"email": "john@example.com", "password": "secret123"}' \
     https://localhost/api/v1/auth/login

# Create post
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" -H "X-CSRF-Token: CSRF_TOKEN" \
     -d '{"title": "My Post", "content": "Hello world"}' \
     https://localhost/api/v1/posts

# Get paginated posts
curl https://localhost/api/v1/posts?limit=10&offset=0

# Upload file
curl -X POST -F "file=@document.pdf" -H "Authorization: Bearer TOKEN" -H "X-CSRF-Token: CSRF_TOKEN" \
     https://localhost/api/v1/upload

# Search posts
curl https://localhost/api/v1/search/posts?q=python&limit=20

# Get admin stats
curl -H "Authorization: Bearer ADMIN_TOKEN" https://localhost/api/v1/admin/stats
"""