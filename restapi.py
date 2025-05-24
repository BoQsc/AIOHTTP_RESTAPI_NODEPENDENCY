import asyncio
import hashlib
import hmac
import json
import logging
import time
import base64
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable

from aiohttp import web
from aiohttp.web_exceptions import (
    HTTPBadRequest,
    HTTPNotFound,
    HTTPUnauthorized,
    HTTPForbidden,
    HTTPInternalServerError, # Used for generic server errors
    HTTPException # Catch this specific base class
)

# --- Configuration & Constants ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_API_PATH = "/api/v1"

JSON_DB_PATH = Path.cwd() / "simple_db.json"
_DATABASE_CACHE: Dict[str, Any] = {
    "users": [],
    "posts": [],
    "next_user_id": 1,
    "next_post_id": 1,
}

_SECRET_KEY = os.urandom(32) # 32 bytes for HMAC-SHA256
_TOKEN_EXPIRATION_SECONDS = 3600 # 1 hour

_SALT_SIZE = 16 # bytes
_HASH_ALGORITHM = 'sha256'
_ITERATIONS = 100000

# --- Custom Exceptions for API Error Handling ---
# IMPORTANT: Inherit from aiohttp's HTTPException classes for proper handling.
# This ensures aiohttp can correctly map these exceptions to HTTP responses.

class NotFoundError(HTTPNotFound):
    def __init__(self, message: str = "Resource not found"):
        # `reason` is for HTTP status line, `text` is for response body
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class BadRequestError(HTTPBadRequest):
    def __init__(self, message: str = "Bad request"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class UnauthorizedError(HTTPUnauthorized):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")

class ForbiddenError(HTTPForbidden):
    def __init__(self, message: str = "Permission denied"):
        super().__init__(reason=message, text=json.dumps({"status": "error", "message": message}), content_type="application/json")


# --- JSON Database Utilities (simulated persistence) ---

async def _load_db_from_file() -> None:
    """Loads the database state from the JSON file into the cache."""
    global _DATABASE_CACHE
    if JSON_DB_PATH.exists():
        try:
            # Use asyncio.to_thread for blocking file I/O to not block the event loop
            content = await asyncio.to_thread(JSON_DB_PATH.read_text, encoding='utf-8')
            _DATABASE_CACHE = json.loads(content)
            logger.info("Database loaded from file.")
        except json.JSONDecodeError:
            logger.error("JSON database file is corrupted. Starting with empty data.")
            _DATABASE_CACHE = {"users": [], "posts": [], "next_user_id": 1, "next_post_id": 1}
        except Exception as e:
            logger.error(f"Error loading database file: {e}. Starting with empty data.")
            _DATABASE_CACHE = {"users": [], "posts": [], "next_user_id": 1, "next_post_id": 1}
    else:
        logger.info("No existing database file found. Initializing empty database.")
        _DATABASE_CACHE = {"users": [], "posts": [], "next_user_id": 1, "next_post_id": 1}

async def _save_db_to_file() -> None:
    """Saves the current database cache state to the JSON file."""
    try:
        # Using a lock for file writes to prevent corruption from concurrent writes
        # In a real app, this would be handled by a proper DB
        async with asyncio.Lock():
            await asyncio.to_thread(JSON_DB_PATH.write_text, json.dumps(_DATABASE_CACHE, indent=4), encoding='utf-8')
            logger.info("Database saved to file.")
    except Exception as e:
        logger.error(f"Error saving database file: {e}")

# --- Security Utilities (Password Hashing & JWT-like Tokens) ---

def _hash_password(password: str) -> str:
    """Hashes a password using PBKDF2 with a random salt."""
    salt = os.urandom(_SALT_SIZE)
    key = hashlib.pbkdf2_hmac(
        _HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        _ITERATIONS
    )
    return base64.b64encode(salt + key).decode('utf-8')

def _verify_password(stored_password_hash: str, provided_password: str) -> bool:
    """Verifies a provided password against a stored hash."""
    try:
        decoded = base64.b64decode(stored_password_hash)
        salt = decoded[:_SALT_SIZE]
        stored_key = decoded[_SALT_SIZE:]

        computed_key = hashlib.pbkdf2_hmac(
            _HASH_ALGORITHM,
            provided_password.encode('utf-8'),
            salt,
            _ITERATIONS
        )
        return hmac.compare_digest(stored_key, computed_key)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def _generate_token(user_id: int) -> str:
    """Generates a simple JWT-like token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": user_id,
        "exp": int(time.time() + _TOKEN_EXPIRATION_SECONDS),
        "iat": int(time.time())
    }

    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

    unsigned_token = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(_SECRET_KEY, unsigned_token, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

def _decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a simple JWT-like token."""
    parts = token.split('.')
    if len(parts) != 3:
        logger.warning("Invalid token format.")
        return None

    encoded_header, encoded_payload, encoded_signature = parts

    try:
        decoded_header_bytes = base64.urlsafe_b64decode(encoded_header + '==')
        decoded_payload_bytes = base64.urlsafe_b64decode(encoded_payload + '==')

        header = json.loads(decoded_header_bytes)
        payload = json.loads(decoded_payload_bytes)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Failed to decode token parts: {e}")
        return None

    unsigned_token = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    expected_signature = hmac.new(_SECRET_KEY, unsigned_token, hashlib.sha256).digest()
    
    if not hmac.compare_digest(expected_signature, base64.urlsafe_b64decode(encoded_signature + '==')):
        logger.warning("Token signature mismatch.")
        return None

    if payload.get("exp") is None or payload["exp"] < time.time():
        logger.warning("Token expired or missing expiration.")
        return None

    return payload

# --- Authentication/Authorization Decorator ---

def login_required(handler: Callable[[web.Request], Awaitable[web.Response]]):
    """Decorator to enforce authentication for API endpoints."""
    async def wrapper(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # Raise aiohttp's HTTPUnauthorized directly
            raise UnauthorizedError("Authorization header 'Bearer <token>' required.")

        token = auth_header.split(" ")[1]
        payload = _decode_token(token)

        if not payload:
            raise UnauthorizedError("Invalid or expired token.")

        request["user_id"] = payload.get("user_id")
        if request["user_id"] is None:
            raise UnauthorizedError("Token does not contain user ID.")

        logger.info(f"User {request['user_id']} authenticated.")
        return await handler(request)
    return wrapper

# --- API Error Handling Decorator ---

def api_error_handler(func: Callable[[web.Request], Awaitable[web.Response]]) -> Callable[[web.Request], Awaitable[web.Response]]:
    """
    Decorator to catch unexpected server exceptions and return consistent JSON responses.
    It re-raises aiohttp.web.HTTPException instances, allowing aiohttp's internal
    error handling to process them into the correct HTTP status codes and bodies.
    Only truly unhandled, generic exceptions are caught and converted to a 500.
    """
    async def handler(request: web.Request) -> web.Response:
        try:
            return await func(request)
        except HTTPException:
            # Re-raise aiohttp's HTTP exceptions (which our custom errors inherit from)
            # This allows aiohttp's internal error handling to format them correctly
            raise
        except asyncio.CancelledError:
            raise # Re-raise CancelledError to allow aiohttp to handle it gracefully
        except Exception as e:
            logger.exception(f"Unhandled server error in {func.__name__}: {e}")
            # For unhandled generic errors, return a default 500 error.
            return web.json_response(
                {"status": "error", "message": "An unexpected server error occurred. Please try again later."},
                status=500,
            )
    return handler

# --- Data Access Layer (DAL) for "Users" and "Posts" ---

class JsonDbAccessor:
    """A simple class to abstract access to our in-memory JSON DB."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        return next((u for u in self._data["users"] if u["id"] == user_id), None)

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        return next((u for u in self._data["users"] if u["username"] == username), None)

    async def create_user(self, username: str, password_hash: str) -> Dict[str, Any]:
        user_id = self._data["next_user_id"]
        new_user = {
            "id": user_id,
            "username": username,
            "password_hash": password_hash,
            "created_at": int(time.time()),
        }
        self._data["users"].append(new_user)
        self._data["next_user_id"] += 1
        await _save_db_to_file()
        logger.info(f"User '{username}' created with ID: {user_id}")
        return new_user

    async def get_post_by_id(self, post_id: int) -> Optional[Dict[str, Any]]:
        return next((p for p in self._data["posts"] if p["id"] == post_id), None)

    async def get_all_posts(self) -> List[Dict[str, Any]]:
        return sorted(self._data["posts"], key=lambda p: p.get("created_at", 0), reverse=True)

    async def create_post(self, title: str, text: str, owner_id: int) -> Dict[str, Any]:
        post_id = self._data["next_post_id"]
        new_post = {
            "id": post_id,
            "title": title,
            "text": text,
            "owner_id": owner_id,
            "editor_id": owner_id,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }
        self._data["posts"].append(new_post)
        self._data["next_post_id"] += 1
        await _save_db_to_file()
        logger.info(f"Post '{title}' created by user {owner_id} with ID: {post_id}")
        return new_post

    async def delete_post(self, post_id: int) -> bool:
        initial_len = len(self._data["posts"])
        self._data["posts"] = [p for p in self._data["posts"] if p["id"] != post_id]
        deleted = len(self._data["posts"]) < initial_len
        if deleted:
            await _save_db_to_file()
            logger.info(f"Post {post_id} deleted.")
        return deleted

    async def update_post(self, post_id: int, updates: Dict[str, Any], editor_id: int) -> Optional[Dict[str, Any]]:
        for i, post in enumerate(self._data["posts"]):
            if post["id"] == post_id:
                updated = False
                if "title" in updates:
                    post["title"] = updates["title"]
                    updated = True
                if "text" in updates:
                    post["text"] = updates["text"]
                    updated = True
                if updated:
                    post["editor_id"] = editor_id
                    post["updated_at"] = int(time.time())
                    await _save_db_to_file()
                    logger.info(f"Post {post_id} updated by user {editor_id}.")
                return post
        return None

# --- Aiohttp Route Definitions ---

router = web.RouteTableDef()

# --- Public Endpoints (No Authentication Required) ---

@router.get("/")
async def root(request: web.Request) -> web.Response:
    """Root endpoint for basic API information."""
    return web.json_response({
        "message": "Welcome to the Blog API!",
        "endpoints": {
            "register": f"POST {BASE_API_PATH}/register",
            "login": f"POST {BASE_API_PATH}/login",
            "posts": f"GET {BASE_API_PATH}/posts",
            "post_detail": f"GET {BASE_API_PATH}/posts/{{id}}"
        }
    })

@router.post(f"{BASE_API_PATH}/register")
@api_error_handler # This now primarily handles generic 500s if anything unexpected happens
async def register_user(request: web.Request) -> web.Response:
    """Registers a new user."""
    try:
        data = await request.json()
    except Exception:
        raise BadRequestError("Request body must be valid JSON.")

    username = data.get("username")
    password = data.get("password")

    if not all([username, password]):
        raise BadRequestError("Missing required fields: 'username' and 'password'.")
    if not isinstance(username, str) or not isinstance(password, str):
        raise BadRequestError("'username' and 'password' must be strings.")
    if len(username) < 3 or len(password) < 6:
        raise BadRequestError("Username must be at least 3 characters, password at least 6 characters.")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]

    if await db_accessor.get_user_by_username(username):
        raise BadRequestError(f"Username '{username}' already exists.")

    hashed_password = _hash_password(password)
    user = await db_accessor.create_user(username, hashed_password)

    token = _generate_token(user["id"])

    return web.json_response(
        {"status": "success", "message": "User registered successfully.", "user_id": user["id"], "token": token},
        status=201
    )

@router.post(f"{BASE_API_PATH}/login")
@api_error_handler
async def login_user(request: web.Request) -> web.Response:
    """Logs in a user and returns a token."""
    try:
        data = await request.json()
    except Exception:
        raise BadRequestError("Request body must be valid JSON.")

    username = data.get("username")
    password = data.get("password")

    if not all([username, password]):
        raise BadRequestError("Missing required fields: 'username' and 'password'.")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    user = await db_accessor.get_user_by_username(username)

    if user and _verify_password(user["password_hash"], password):
        token = _generate_token(user["id"])
        return web.json_response({"status": "success", "message": "Login successful.", "token": token})
    else:
        raise UnauthorizedError("Invalid username or password.")

@router.get(f"{BASE_API_PATH}/posts")
@api_error_handler
async def list_posts(request: web.Request) -> web.Response:
    """Lists all blog posts (publicly accessible)."""
    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    posts = await db_accessor.get_all_posts()
    return web.json_response({"status": "success", "data": posts})

@router.get(f"{BASE_API_PATH}/posts/{{post_id}}")
@api_error_handler
async def get_post(request: web.Request) -> web.Response:
    """Retrieves a single blog post by ID (publicly accessible)."""
    post_id_str = request.match_info.get("post_id")
    try:
        post_id = int(post_id_str)
    except (TypeError, ValueError):
        raise BadRequestError(f"Invalid post ID format: '{post_id_str}'. Must be an integer.")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    post = await db_accessor.get_post_by_id(post_id)
    if not post:
        raise NotFoundError(f"Post with ID {post_id} not found.")

    return web.json_response({"status": "success", "data": post})

# --- Authenticated Endpoints ---

@router.post(f"{BASE_API_PATH}/posts")
@login_required
@api_error_handler
async def create_post(request: web.Request) -> web.Response:
    """Creates a new blog post (requires authentication)."""
    try:
        data = await request.json()
    except Exception:
        raise BadRequestError("Request body must be valid JSON.")

    title = data.get("title")
    text = data.get("text")
    owner_id = request["user_id"]

    if not all([title, text]):
        raise BadRequestError("Missing required fields: 'title' and 'text'.")
    if not isinstance(title, str) or not isinstance(text, str):
         raise BadRequestError("'title' and 'text' must be strings.")
    if len(title) > 255:
        raise BadRequestError("Title too long (max 255 characters).")
    if len(text) < 10:
        raise BadRequestError("Post text too short (min 10 characters).")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    new_post = await db_accessor.create_post(title, text, owner_id)
    return web.json_response({"status": "success", "data": new_post}, status=201)

@router.delete(f"{BASE_API_PATH}/posts/{{post_id}}")
@login_required
@api_error_handler
async def delete_post(request: web.Request) -> web.Response:
    """Deletes a blog post (requires authentication and ownership)."""
    post_id_str = request.match_info.get("post_id")
    try:
        post_id = int(post_id_str)
    except (TypeError, ValueError):
        raise BadRequestError(f"Invalid post ID format: '{post_id_str}'. Must be an integer.")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    current_user_id = request["user_id"]

    post_to_delete = await db_accessor.get_post_by_id(post_id)
    if not post_to_delete:
        raise NotFoundError(f"Post with ID {post_id} not found.")
    if post_to_delete["owner_id"] != current_user_id:
        raise ForbiddenError("You can only delete your own posts.")

    deleted = await db_accessor.delete_post(post_id)
    if not deleted:
        raise HTTPInternalServerError("Failed to delete post for an unknown reason.") # Should not happen if ownership check passed
    return web.json_response({"status": "success", "message": f"Post {post_id} deleted successfully."})

@router.patch(f"{BASE_API_PATH}/posts/{{post_id}}")
@login_required
@api_error_handler
async def update_post(request: web.Request) -> web.Response:
    """Updates specific fields of a blog post (requires authentication and ownership)."""
    post_id_str = request.match_info.get("post_id")
    try:
        post_id = int(post_id_str)
    except (TypeError, ValueError):
        raise BadRequestError(f"Invalid post ID format: '{post_id_str}'. Must be an integer.")

    try:
        data = await request.json()
    except Exception:
        raise BadRequestError("Request body must be valid JSON.")

    updates = {}
    allowed_fields = {"title", "text"}

    for field, value in data.items():
        if field in allowed_fields:
            if not isinstance(value, str):
                raise BadRequestError(f"Field '{field}' must be a string.")
            if field == "title" and len(value) > 255:
                raise BadRequestError("Title too long (max 255 characters).")
            if field == "text" and len(value) < 10:
                raise BadRequestError("Post text too short (min 10 characters).")
            updates[field] = value
        else:
            logger.warning(f"Attempted to update disallowed field: {field}")

    if not updates:
        raise BadRequestError("No valid fields provided for update. Allowed fields: 'title', 'text'.")

    db_accessor: JsonDbAccessor = request.app["DB_ACCESSOR"]
    current_user_id = request["user_id"]

    post_to_update = await db_accessor.get_post_by_id(post_id)
    if not post_to_update:
        raise NotFoundError(f"Post with ID {post_id} not found.")
    if post_to_update["owner_id"] != current_user_id:
        raise ForbiddenError("You can only edit your own posts.")

    updated_post = await db_accessor.update_post(post_id, updates, current_user_id)
    if not updated_post:
         raise HTTPInternalServerError("Failed to update post for an unknown reason.")

    return web.json_response({"status": "success", "data": updated_post})

# --- Application Initialization ---

async def init_app() -> web.Application:
    """Initializes the aiohttp web application."""
    app = web.Application()
    app.add_routes(router)

    await _load_db_from_file()
    app["DB_ACCESSOR"] = JsonDbAccessor(_DATABASE_CACHE)

    logger.info("Aiohttp application initialized.")
    return app

# --- Main Entry Point ---

if __name__ == "__main__":
    logger.info("Starting aiohttp web application...")
    web.run_app(init_app(), host='0.0.0.0', port=8080)