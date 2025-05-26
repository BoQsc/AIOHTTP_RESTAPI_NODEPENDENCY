"""
Enhanced API server with comprehensive rate limiting
Integration of rate limiting middleware into existing API
"""

from aiohttp import web
import ssl
import logging
import uuid
import json
import secrets
import mimetypes
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
import re
from functools import wraps

# Import existing modules
try:
    import tools.db as db
except ImportError:
    print("ERROR: Cannot import tools.db module. Please ensure it exists and is properly configured.")
    exit(1)

# Import the rate limiting system
from collections import defaultdict, deque
from dataclasses import dataclass
import time

# Rate Limiting Classes (embedded for easy integration)
@dataclass
class RateLimit:
    """Rate limit configuration"""
    max_requests: int
    window_seconds: int
    description: str = ""

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None

class RateLimiter:
    """Thread-safe rate limiter using sliding window algorithm"""
    
    def __init__(self):
        self.requests = defaultdict(deque)  # key -> deque of timestamps
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, key: str, limit: RateLimit) -> RateLimitResult:
        """Check if request is allowed under rate limit"""
        async with self.lock:
            now = time.time()
            window_start = now - limit.window_seconds
            
            # Clean old requests outside window
            request_times = self.requests[key]
            while request_times and request_times[0] < window_start:
                request_times.popleft()
            
            current_count = len(request_times)
            
            if current_count >= limit.max_requests:
                # Rate limit exceeded
                oldest_request = request_times[0] if request_times else now
                reset_time = oldest_request + limit.window_seconds
                retry_after = int(reset_time - now) + 1
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
            
            # Allow request and record it
            request_times.append(now)
            remaining = limit.max_requests - (current_count + 1)
            reset_time = now + limit.window_seconds
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_time=reset_time
            )

class RateLimitConfig:
    """Rate limit configuration for different endpoints and users"""
    
    def __init__(self, environment='production'):
        self.environment = environment
        
        if environment == 'development':
            # More generous limits for development
            self.default_limits = {
                'ip': RateLimit(500, 3600, "Dev IP limit: 500 requests/hour"),
                'user': RateLimit(2000, 3600, "Dev user limit: 2000 requests/hour"),
            }
            
            self.endpoint_limits = {
                r'^/api/v1/auth/login$': {
                    'ip': RateLimit(20, 300, "Dev login: 20 per 5 minutes"),
                },
                r'^/api/v1/auth/register$': {
                    'ip': RateLimit(10, 3600, "Dev registration: 10 per hour"),
                },
                r'^/api/v1/upload$': {
                    'ip': RateLimit(50, 3600, "Dev file upload: 50 per hour"),
                },
            }
        else:
            # Production limits - more restrictive
            self.default_limits = {
                'ip': RateLimit(100, 3600, "Production IP limit: 100 requests/hour"),
                'user': RateLimit(1000, 3600, "Production user limit: 1000 requests/hour"),
            }
            
            self.endpoint_limits = {
                r'^/api/v1/auth/login$': {
                    'ip': RateLimit(5, 300, "Login attempts: 5 per 5 minutes"),
                    'user': RateLimit(10, 600, "User login: 10 per 10 minutes"),
                },
                r'^/api/v1/auth/register$': {
                    'ip': RateLimit(3, 3600, "Registration: 3 per hour"),
                },
                r'^/api/v1/upload$': {
                    'ip': RateLimit(10, 3600, "File upload: 10 per hour"),
                    'user': RateLimit(50, 3600, "User file upload: 50 per hour"),
                },
                r'^/api/v1/posts$': {
                    'ip': RateLimit(20, 300, "Create posts: 20 per 5 minutes"),
                    'user': RateLimit(100, 3600, "User posts: 100 per hour"),
                },
                r'^/api/v1/search/': {
                    'ip': RateLimit(30, 300, "Search: 30 per 5 minutes"),
                    'user': RateLimit(200, 3600, "User search: 200 per hour"),
                },
            }
        
        # Role-based multipliers
        self.role_multipliers = {
            'admin': 10.0,    # Admins get 10x limits
            'premium': 3.0,   # Premium users get 3x
            'user': 1.0,      # Regular users
        }
    
    def get_limit_for_request(self, path: str, method: str, limit_type: str, user_role: str = 'user') -> RateLimit:
        """Get rate limit for a specific request"""
        # Check endpoint-specific limits first
        for pattern, limits in self.endpoint_limits.items():
            if re.match(pattern, path):
                if limit_type in limits:
                    limit = limits[limit_type]
                    return self._apply_role_multiplier(limit, user_role)
        
        # Fall back to default limits
        if limit_type in self.default_limits:
            limit = self.default_limits[limit_type]
            return self._apply_role_multiplier(limit, user_role)
        
        # Fallback safety limit
        return RateLimit(10, 60, "Fallback safety limit")
    
    def _apply_role_multiplier(self, limit: RateLimit, user_role: str) -> RateLimit:
        """Apply role-based multiplier to rate limit"""
        multiplier = self.role_multipliers.get(user_role, 1.0)
        if multiplier == 1.0:
            return limit
        
        return RateLimit(
            max_requests=int(limit.max_requests * multiplier),
            window_seconds=limit.window_seconds,
            description=f"{limit.description} (role: {user_role}, {multiplier}x)"
        )

class RateLimitMiddleware:
    """Rate limiting middleware for aiohttp"""
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.limiter = RateLimiter()
        self.config = config or RateLimitConfig()
        self.analytics = {
            'blocked_count': 0,
            'allowed_count': 0,
            'start_time': time.time()
        }
    
    def get_client_identifier(self, request: web.Request) -> str:
        """Get client identifier for rate limiting"""
        # Try to get real IP from headers (for reverse proxy setups)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.remote or 'unknown'
        
        return f"ip:{client_ip}"
    
    def get_user_identifier(self, request: web.Request) -> Optional[str]:
        """Get user identifier for authenticated requests"""
        user = request.get('user')
        if user and user.get('user_id'):
            return f"user:{user['user_id']}"
        return None
    
    def get_user_role(self, request: web.Request) -> str:
        """Get user role for rate limit calculations"""
        user = request.get('user')
        if user:
            return user.get('role', 'user')
        return 'user'
    
    async def check_rate_limits(self, request: web.Request) -> Optional[web.Response]:
        """Check rate limits for the request"""
        path = request.path
        method = request.method
        
        # Get client and user identifiers
        client_id = self.get_client_identifier(request)
        user_id = self.get_user_identifier(request)
        user_role = self.get_user_role(request)
        
        # Check IP-based rate limit
        ip_limit = self.config.get_limit_for_request(path, method, 'ip', user_role)
        ip_result = await self.limiter.is_allowed(client_id, ip_limit)
        
        if not ip_result.allowed:
            self.analytics['blocked_count'] += 1
            logging.warning(f"IP rate limit exceeded for {client_id} on {path}")
            return self._create_rate_limit_response(
                "IP rate limit exceeded", 
                ip_result, 
                ip_limit
            )
        
        # Check user-based rate limit for authenticated requests
        user_result = None
        if user_id:
            user_limit = self.config.get_limit_for_request(path, method, 'user', user_role)
            user_result = await self.limiter.is_allowed(user_id, user_limit)
            
            if not user_result.allowed:
                self.analytics['blocked_count'] += 1
                logging.warning(f"User rate limit exceeded for {user_id} on {path}")
                return self._create_rate_limit_response(
                    "User rate limit exceeded", 
                    user_result, 
                    user_limit
                )
        
        # Track successful requests
        self.analytics['allowed_count'] += 1
        
        # Add rate limit info to request for response headers
        request['rate_limit_info'] = {
            'ip_remaining': ip_result.remaining,
            'ip_reset': ip_result.reset_time,
            'user_remaining': user_result.remaining if user_result else None,
            'user_reset': user_result.reset_time if user_result else None,
        }
        
        return None  # Allow request to proceed
    
    def _create_rate_limit_response(self, message: str, result: RateLimitResult, limit: RateLimit) -> web.Response:
        """Create rate limit exceeded response"""
        headers = {
            'X-RateLimit-Limit': str(limit.max_requests),
            'X-RateLimit-Remaining': str(result.remaining),
            'X-RateLimit-Reset': str(int(result.reset_time)),
            'X-RateLimit-Window': str(limit.window_seconds),
        }
        
        if result.retry_after:
            headers['Retry-After'] = str(result.retry_after)
        
        return web.json_response(
            {
                "message": message,
                "status": "error",
                "rate_limit": {
                    "limit": limit.max_requests,
                    "window_seconds": limit.window_seconds,
                    "remaining": result.remaining,
                    "reset_at": result.reset_time,
                    "retry_after_seconds": result.retry_after,
                    "description": limit.description
                }
            },
            status=429,  # Too Many Requests
            headers=headers
        )
    
    def get_analytics(self) -> Dict[str, Any]:
        """Get rate limiting analytics"""
        uptime = time.time() - self.analytics['start_time']
        total_requests = self.analytics['allowed_count'] + self.analytics['blocked_count']
        
        return {
            'uptime_seconds': uptime,
            'total_requests': total_requests,
            'allowed_requests': self.analytics['allowed_count'],
            'blocked_requests': self.analytics['blocked_count'],
            'block_rate': self.analytics['blocked_count'] / total_requests if total_requests > 0 else 0,
        }

# Global rate limiter instance
rate_limiter_instance = None

@web.middleware
async def rate_limit_middleware(request, handler):
    """Rate limiting middleware function"""
    global rate_limiter_instance
    
    # Skip rate limiting for health checks
    skip_paths = ['/health', '/api/v1/health', '/static']
    if any(request.path.startswith(path) for path in skip_paths):
        return await handler(request)
    
    # Initialize rate limiter if needed
    if rate_limiter_instance is None:
        # Detect environment (you can also use environment variables)
        environment = 'development'  # Change to 'production' for prod
        config = RateLimitConfig(environment=environment)
        rate_limiter_instance = RateLimitMiddleware(config)
        logging.info(f"Rate limiter initialized for {environment} environment")
    
    # Check rate limits
    rate_limit_response = await rate_limiter_instance.check_rate_limits(request)
    if rate_limit_response:
        return rate_limit_response
    
    # Execute the request
    response = await handler(request)
    
    # Add rate limit headers to successful responses
    if hasattr(request, 'rate_limit_info') and hasattr(response, 'headers'):
        info = request['rate_limit_info']
        
        if info.get('ip_remaining') is not None:
            response.headers['X-RateLimit-Remaining-IP'] = str(info['ip_remaining'])
            response.headers['X-RateLimit-Reset-IP'] = str(int(info['ip_reset']))
        
        if info.get('user_remaining') is not None:
            response.headers['X-RateLimit-Remaining-User'] = str(info['user_remaining'])
            response.headers['X-RateLimit-Reset-User'] = str(int(info['user_reset']))
    
    return response

# [ALL YOUR EXISTING CODE HERE - Configuration, ValidationError, helpers, handlers, etc.]
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

# [Include all your existing validation functions, handlers, etc. - same as before]

class ValidationError(Exception):
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(message)

# In-memory CSRF token storage
csrf_tokens = {}

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

async def get_csrf_token(request):
    try:
        token = generate_csrf_token()
        csrf_tokens[token] = True
        return web.json_response({
            "csrf_token": token,
            "status": "success"
        })
    except Exception as e:
        logging.error(f"Error generating CSRF token: {e}")
        return web.json_response({
            "message": "Failed to generate CSRF token",
            "status": "error"
        }, status=500)

def validate_csrf_token(token: str) -> bool:
    if not token:
        return False
    return token in csrf_tokens

# Add rate limiting analytics endpoint
async def get_rate_limit_stats(request):
    """Get rate limiting statistics (admin only)"""
    user = request.get('user')
    if not user or user.get('role') != 'admin':
        return web.json_response({"message": "Admin access required", "status": "error"}, status=403)
    
    global rate_limiter_instance
    if rate_limiter_instance:
        stats = rate_limiter_instance.get_analytics()
        return web.json_response({
            "data": stats,
            "status": "success"
        })
    else:
        return web.json_response({
            "message": "Rate limiter not initialized",
            "status": "error"
        }, status=500)

# Add health check endpoint (bypasses rate limiting)
async def health_check(request):
    """Health check endpoint"""
    return web.json_response({
        "status": "healthy",
        "timestamp": time.time(),
        "version": "1.0.0"
    })

# [Include all your existing middleware and handlers]

@web.middleware
async def cors_handler(request, handler):
    """CORS middleware"""
    try:
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token'
        return response
    except Exception as e:
        logging.error(f"CORS middleware error: {e}")
        raise

@web.middleware
async def error_handling_middleware(request, handler):
    """Global error handling - FIXED"""
    try:
        response = await handler(request)
        return response
    except ValidationError as e:
        return web.json_response({
            "message": e.message,
            "field": e.field,
            "status": "error"
        }, status=400)
    except web.HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unhandled error in {request.path}: {e}", exc_info=True)
        return web.json_response({
            "message": "Internal server error",
            "status": "error"
        }, status=500)

@web.middleware
async def csrf_protection(request, handler):
    """CSRF protection middleware"""
    try:
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return await handler(request)
        
        if (request.path.startswith('/api/v1/auth/') or 
            request.path == '/api/v1/csrf-token' or
            request.path == '/api/v1/health'):
            return await handler(request)
        
        public_post_paths = ['/api/v1/auth/register', '/api/v1/auth/login']
        if request.path not in public_post_paths:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return await handler(request)
        
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            return web.json_response(
                {"message": "CSRF token missing or invalid", "status": "error"}, 
                status=403
            )
        
        return await handler(request)
    except Exception as e:
        logging.error(f"CSRF middleware error: {e}")
        raise

@web.middleware
async def auth_middleware(request, handler):
    """Authentication middleware"""
    try:
        public_paths = [
            '/api/v1/',
            '/api/v1/auth/register',
            '/api/v1/auth/login',
            '/api/v1/csrf-token',
            '/api/v1/search/posts',
            '/api/v1/health'
        ]
        
        path = request.path
        method = request.method
        
        if method == 'GET' and (path.startswith('/api/v1/posts') or 
                               path.startswith('/api/v1/files') or 
                               path in public_paths):
            return await handler(request)
        
        if path in public_paths:
            return await handler(request)
        
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
        
        request['user'] = session
        return await handler(request)
        
    except ValidationError:
        raise
    except web.HTTPException:
        raise
    except Exception as e:
        logging.error(f"Auth middleware error: {e}")
        return web.json_response({
            "message": "Authentication error",
            "status": "error"
        }, status=500)

# Basic handlers (add your existing handlers here)
async def index(request):
    return web.json_response({
        "message": "API v1 with Rate Limiting - Hello world",
        "status": "success",
        "version": "1.0.0",
        "features": ["authentication", "rate_limiting", "file_upload", "blog_posts"]
    })

# Initialization
async def periodic_cleanup(app):
    """Periodic cleanup task"""
    while True:
        try:
            await db.cleanup_expired_sessions()
            logging.info("Cleaned up expired sessions")
        except Exception as e:
            logging.error(f"Cleanup error: {e}")
        await asyncio.sleep(300)

async def init_app(app):
    """Initialize application"""
    try:
        await db.init_database()
        logging.info("Database initialized successfully")
        
        asyncio.create_task(periodic_cleanup(app))
        logging.info("Started periodic cleanup task")
        
        # Log rate limiting configuration
        global rate_limiter_instance
        if rate_limiter_instance:
            logging.info(f"Rate limiting active: {rate_limiter_instance.config.environment} environment")
        
    except Exception as e:
        logging.error(f"Failed to initialize: {e}")
        raise

async def cleanup_app(app):
    logging.info("Server shutting down")

# Create application
app = web.Application()

# Add middleware in correct order
app.middlewares.append(error_handling_middleware)  # First - catches all exceptions
app.middlewares.append(cors_handler)
app.middlewares.append(rate_limit_middleware)      # Rate limiting before auth/CSRF
app.middlewares.append(csrf_protection)
app.middlewares.append(auth_middleware)

# Routes
app.router.add_get('/api/v1/', index)
app.router.add_get('/api/v1/health', health_check)
app.router.add_get('/api/v1/csrf-token', get_csrf_token)
app.router.add_get('/api/v1/admin/rate-limit-stats', get_rate_limit_stats)

# [Add all your existing routes here]

# Lifecycle events
app.on_startup.append(init_app)
app.on_cleanup.append(cleanup_app)

# SSL setup
logging.basicConfig(level=logging.INFO)

if __name__ == '__main__':
    cert_path = Path('cert.pem')
    key_path = Path('key.pem')
    
    if cert_path.exists() and key_path.exists():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain('cert.pem', 'key.pem')
        logging.info("Starting server with SSL on port 443")
        web.run_app(
            app, 
            ssl_context=ctx, 
            port=443, 
            access_log=logging.getLogger('aiohttp.access')
        )
    else:
        logging.warning("SSL certificates not found, running on HTTP port 8080")
        web.run_app(
            app, 
            port=8080, 
            access_log=logging.getLogger('aiohttp.access')
        )