#!/usr/bin/env python3
"""
Simple Blog REST API Server
Single standalone file - just run with: python restapi.py
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import base64
import os
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable
from collections import defaultdict, deque

from aiohttp import web
from aiohttp.web_exceptions import (
    HTTPBadRequest, HTTPNotFound, HTTPUnauthorized, 
    HTTPForbidden, HTTPInternalServerError, HTTPTooManyRequests, HTTPException
)

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8080
DB_FILE = Path('simple_db.json')
SECRET_KEY_FILE = Path('secret.key')
RATE_LIMIT_REQUESTS = 60  # requests per minute
TOKEN_EXPIRATION = 3600   # 1 hour

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global state
_DATABASE_CACHE = {"users": [], "posts": [], "next_user_id": 1, "next_post_id": 1}
_DB_LOCK = asyncio.Lock()
_SECRET_KEY = b''
_RATE_LIMITER = None

# --- Custom Exceptions ---
class APIError(HTTPException):
    def __init__(self, message: str, status_code: int):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")
        self.status_code = status_code

class BadRequest(HTTPBadRequest):
    def __init__(self, message: str = "Bad request"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class NotFound(HTTPNotFound):
    def __init__(self, message: str = "Not found"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class Unauthorized(HTTPUnauthorized):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class Forbidden(HTTPForbidden): 
    def __init__(self, message: str = "Forbidden"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class TooManyRequests(HTTPTooManyRequests):
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

# --- Rate Limiter ---
class SimpleRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
    
    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        user_requests = self.requests[identifier]
        
        # Remove old requests
        while user_requests and user_requests[0] < now - self.window_seconds:
            user_requests.popleft()
        
        # Check limit
        if len(user_requests) < self.max_requests:
            user_requests.append(now)
            return True
        return False

# --- Secret Key Management ---
def load_or_create_secret_key() -> bytes:
    if SECRET_KEY_FILE.exists():
        try:
            return SECRET_KEY_FILE.read_bytes()
        except Exception:
            pass
    
    # Create new key
    secret_key = os.urandom(32)
    try:
        SECRET_KEY_FILE.write_bytes(secret_key)
        os.chmod(SECRET_KEY_FILE, 0o600)
        logger.info("New secret key created")
    except Exception as e:
        logger.warning(f"Could not save secret key: {e}")
    return secret_key

# --- Database Operations ---
async def load_database():
    global _DATABASE_CACHE
    if not DB_FILE.exists():
        logger.info("Starting with empty database")
        return
    
    try:
        content = await asyncio.to_thread(DB_FILE.read_text, encoding='utf-8')
        _DATABASE_CACHE = json.loads(content)
        logger.info(f"Database loaded - {len(_DATABASE_CACHE['users'])} users, {len(_DATABASE_CACHE['posts'])} posts")
    except Exception as e:
        logger.error(f"Error loading database: {e}")
        _DATABASE_CACHE = {"users": [], "posts": [], "next_user_id": 1, "next_post_id": 1}

async def save_database():
    try:
        async with _DB_LOCK:
            # Atomic write using temporary file
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', 
                                           dir=DB_FILE.parent, delete=False) as tmp:
                json.dump(_DATABASE_CACHE, tmp, indent=2)
                temp_path = tmp.name
            
            await asyncio.to_thread(shutil.move, temp_path, DB_FILE)
    except Exception as e:
        logger.error(f"Error saving database: {e}")
        if 'temp_path' in locals():
            try:
                os.unlink(temp_path)
            except:
                pass

# --- Security Functions ---
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        decoded = base64.b64decode(stored_hash)
        salt, stored_key = decoded[:16], decoded[16:]
        computed_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(stored_key, computed_key)
    except:
        return False

def generate_token(user_id: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user_id": user_id, "exp": int(time.time() + TOKEN_EXPIRATION)}
    
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    
    unsigned = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(_SECRET_KEY, unsigned, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        encoded_header, encoded_payload, encoded_signature = parts
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload + '=='))
        
        # Verify signature
        unsigned = f"{encoded_header}.{encoded_payload}".encode()
        expected = hmac.new(_SECRET_KEY, unsigned, hashlib.sha256).digest()
        
        if not hmac.compare_digest(expected, base64.urlsafe_b64decode(encoded_signature + '==')):
            return None
        
        # Check expiration
        if payload.get("exp", 0) < time.time():
            return None
        
        return payload
    except:
        return None

# --- Decorators ---
def rate_limit(func):
    async def wrapper(request):
        client_ip = request.remote or "unknown"
        if not _RATE_LIMITER.is_allowed(client_ip):
            raise TooManyRequests("Rate limit exceeded")
        return await func(request)
    return wrapper

def login_required(func):
    async def wrapper(request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise Unauthorized("Bearer token required")
        
        token = auth_header.split(" ")[1]
        payload = decode_token(token)
        if not payload:
            raise Unauthorized("Invalid or expired token")
        
        request["user_id"] = payload["user_id"]
        return await func(request)
    return wrapper

def error_handler(func):
    async def wrapper(request):
        try:
            return await func(request)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unhandled error in {func.__name__}")
            return web.json_response({"status": "error", "message": "Internal server error"}, status=500)
    return wrapper

# --- Database Access ---
class DB:
    @staticmethod
    def get_user_by_username(username: str) -> Optional[Dict]:
        return next((u for u in _DATABASE_CACHE["users"] if u["username"] == username), None)
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[Dict]:
        return next((u for u in _DATABASE_CACHE["users"] if u["id"] == user_id), None)
    
    @staticmethod
    async def create_user(username: str, password: str) -> Dict:
        user_id = _DATABASE_CACHE["next_user_id"]
        user = {
            "id": user_id,
            "username": username,
            "password_hash": hash_password(password),
            "created_at": int(time.time())
        }
        _DATABASE_CACHE["users"].append(user)
        _DATABASE_CACHE["next_user_id"] += 1
        await save_database()
        return user
    
    @staticmethod
    def get_post_by_id(post_id: int) -> Optional[Dict]:
        return next((p for p in _DATABASE_CACHE["posts"] if p["id"] == post_id), None)
    
    @staticmethod
    def get_all_posts() -> List[Dict]:
        return sorted(_DATABASE_CACHE["posts"], key=lambda p: p["created_at"], reverse=True)
    
    @staticmethod
    async def create_post(title: str, text: str, owner_id: int) -> Dict:
        post_id = _DATABASE_CACHE["next_post_id"]
        post = {
            "id": post_id,
            "title": title,
            "text": text,
            "owner_id": owner_id,
            "created_at": int(time.time()),
            "updated_at": int(time.time())
        }
        _DATABASE_CACHE["posts"].append(post)
        _DATABASE_CACHE["next_post_id"] += 1
        await save_database()
        return post
    
    @staticmethod
    async def update_post(post_id: int, updates: Dict, editor_id: int) -> Optional[Dict]:
        for post in _DATABASE_CACHE["posts"]:
            if post["id"] == post_id:
                if "title" in updates:
                    post["title"] = updates["title"]
                if "text" in updates:
                    post["text"] = updates["text"]
                post["updated_at"] = int(time.time())
                await save_database()
                return post
        return None
    
    @staticmethod
    async def delete_post(post_id: int) -> bool:
        initial_len = len(_DATABASE_CACHE["posts"])
        _DATABASE_CACHE["posts"] = [p for p in _DATABASE_CACHE["posts"] if p["id"] != post_id]
        if len(_DATABASE_CACHE["posts"]) < initial_len:
            await save_database()
            return True
        return False

# --- Route Handlers ---
routes = web.RouteTableDef()

@routes.get('/health')
async def health_check(request):
    return web.json_response({
        "status": "healthy",
        "timestamp": int(time.time()),
        "users": len(_DATABASE_CACHE["users"]),
        "posts": len(_DATABASE_CACHE["posts"])
    })

@routes.get('/')
async def root(request):
    return web.json_response({
        "message": "Simple Blog API",
        "endpoints": {
            "health": "GET /health",
            "register": "POST /api/v1/register",
            "login": "POST /api/v1/login", 
            "posts": "GET /api/v1/posts",
            "create_post": "POST /api/v1/posts",
            "get_post": "GET /api/v1/posts/{id}",
            "update_post": "PATCH /api/v1/posts/{id}",
            "delete_post": "DELETE /api/v1/posts/{id}"
        }
    })

@routes.post('/api/v1/register')
@rate_limit
@error_handler
async def register(request):
    try:
        data = await request.json()
    except:
        raise BadRequest("Invalid JSON")
    
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        raise BadRequest("Username and password required")
    
    if len(username) < 3 or len(password) < 6:
        raise BadRequest("Username min 3 chars, password min 6 chars")
    
    if DB.get_user_by_username(username):
        raise BadRequest("Username already exists")
    
    user = await DB.create_user(username, password)
    token = generate_token(user["id"])
    
    return web.json_response({
        "status": "success",
        "message": "User registered",
        "user_id": user["id"],
        "token": token
    }, status=201)

@routes.post('/api/v1/login')
@rate_limit
@error_handler
async def login(request):
    try:
        data = await request.json()
    except:
        raise BadRequest("Invalid JSON")
    
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        raise BadRequest("Username and password required")
    
    user = DB.get_user_by_username(username)
    if not user or not verify_password(user["password_hash"], password):
        raise Unauthorized("Invalid credentials")
    
    token = generate_token(user["id"])
    return web.json_response({
        "status": "success", 
        "message": "Login successful",
        "token": token
    })

@routes.get('/api/v1/posts')
@rate_limit
@error_handler
async def list_posts(request):
    posts = DB.get_all_posts()
    return web.json_response({"status": "success", "data": posts})

@routes.get('/api/v1/posts/{post_id}')
@rate_limit  
@error_handler
async def get_post(request):
    try:
        post_id = int(request.match_info["post_id"])
    except (ValueError, KeyError):
        raise BadRequest("Invalid post ID")
    
    post = DB.get_post_by_id(post_id)
    if not post:
        raise NotFound("Post not found")
    
    return web.json_response({"status": "success", "data": post})

@routes.post('/api/v1/posts')
@login_required
@rate_limit
@error_handler
async def create_post(request):
    try:
        data = await request.json()
    except:
        raise BadRequest("Invalid JSON")
    
    title = data.get("title", "").strip()
    text = data.get("text", "").strip()
    
    if not title or not text:
        raise BadRequest("Title and text required")
    
    if len(title) > 255:
        raise BadRequest("Title too long")
    
    if len(text) < 10:
        raise BadRequest("Text too short")
    
    post = await DB.create_post(title, text, request["user_id"])
    return web.json_response({"status": "success", "data": post}, status=201)

@routes.patch('/api/v1/posts/{post_id}')
@login_required
@rate_limit
@error_handler
async def update_post(request):
    try:
        post_id = int(request.match_info["post_id"])
    except (ValueError, KeyError):
        raise BadRequest("Invalid post ID")
    
    try:
        data = await request.json()
    except:
        raise BadRequest("Invalid JSON")
    
    post = DB.get_post_by_id(post_id)
    if not post:
        raise NotFound("Post not found")
    
    if post["owner_id"] != request["user_id"]:
        raise Forbidden("Can only edit your own posts")
    
    updates = {}
    if "title" in data:
        title = data["title"].strip()
        if not title or len(title) > 255:
            raise BadRequest("Invalid title")
        updates["title"] = title
    
    if "text" in data:
        text = data["text"].strip()
        if not text or len(text) < 10:
            raise BadRequest("Invalid text")
        updates["text"] = text
    
    if not updates:
        raise BadRequest("No valid fields to update")
    
    updated_post = await DB.update_post(post_id, updates, request["user_id"])
    return web.json_response({"status": "success", "data": updated_post})

@routes.delete('/api/v1/posts/{post_id}')
@login_required
@rate_limit
@error_handler
async def delete_post(request):
    try:
        post_id = int(request.match_info["post_id"])
    except (ValueError, KeyError):
        raise BadRequest("Invalid post ID")
    
    post = DB.get_post_by_id(post_id)
    if not post:
        raise NotFound("Post not found")
    
    if post["owner_id"] != request["user_id"]:
        raise Forbidden("Can only delete your own posts")
    
    await DB.delete_post(post_id)
    return web.json_response({"status": "success", "message": "Post deleted"})

# --- Application Setup ---
async def init_app():
    global _SECRET_KEY, _RATE_LIMITER
    
    _SECRET_KEY = load_or_create_secret_key()
    _RATE_LIMITER = SimpleRateLimiter(RATE_LIMIT_REQUESTS, 60)
    
    await load_database()
    
    app = web.Application()
    app.add_routes(routes)
    
    return app

# --- Main ---
if __name__ == "__main__":
    logger.info(f"Starting Blog API on {HOST}:{PORT}")
    logger.info(f"Database: {DB_FILE}")
    logger.info(f"Rate limit: {RATE_LIMIT_REQUESTS} requests/minute")
    
    try:
        web.run_app(init_app(), host=HOST, port=PORT)
    except KeyboardInterrupt:
        logger.info("Server stopped")
    except Exception as e:
        logger.error(f"Server error: {e}")
