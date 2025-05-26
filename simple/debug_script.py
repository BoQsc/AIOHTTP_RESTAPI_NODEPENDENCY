#!/usr/bin/env python3
"""
Debug script to identify issues with the API server
"""

import asyncio
import sys
import traceback
from pathlib import Path

async def test_database_import():
    """Test if database module can be imported and initialized"""
    print("🔍 Testing database import...")
    try:
        # Try to import the database module
        sys.path.append('.')  # Add current directory to path
        import tools.db as db
        print("✅ Database module imported successfully")
        
        # Test database initialization
        print("🔍 Testing database initialization...")
        await db.init_database()
        print("✅ Database initialized successfully")
        
        return True
    except ImportError as e:
        print(f"❌ Cannot import database module: {e}")
        print("💡 Please ensure 'tools/db.py' exists and is properly configured")
        return False
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        print(f"📋 Full traceback:\n{traceback.format_exc()}")
        return False

async def test_basic_handlers():
    """Test basic handler functions"""
    print("\n🔍 Testing basic handlers...")
    try:
        from aiohttp import web
        from aiohttp.test_utils import make_mocked_request
        
        # Import the API module
        if Path('api_fixed.py').exists():
            sys.path.append('.')
            import api_fixed as api
        else:
            import api
            
        # Test the index handler
        request = make_mocked_request('GET', '/api/v1/')
        response = await api.index(request)
        
        if hasattr(response, 'status') and response.status == 200:
            print("✅ Index handler working correctly")
            return True
        else:
            print(f"❌ Index handler returned unexpected response: {response}")
            return False
            
    except Exception as e:
        print(f"❌ Handler test error: {e}")
        print(f"📋 Full traceback:\n{traceback.format_exc()}")
        return False

async def test_csrf_token_handler():
    """Test CSRF token handler specifically"""
    print("\n🔍 Testing CSRF token handler...")
    try:
        from aiohttp.test_utils import make_mocked_request
        
        # Import the API module
        if Path('api_fixed.py').exists():
            import api_fixed as api
        else:
            import api
            
        # Test the CSRF token handler
        request = make_mocked_request('GET', '/api/v1/csrf-token')
        response = await api.get_csrf_token(request)
        
        if hasattr(response, 'status') and response.status == 200:
            print("✅ CSRF token handler working correctly")
            return True
        else:
            print(f"❌ CSRF token handler returned unexpected response: {response}")
            return False
            
    except Exception as e:
        print(f"❌ CSRF token handler test error: {e}")
        print(f"📋 Full traceback:\n{traceback.format_exc()}")
        return False

def check_ssl_certificates():
    """Check if SSL certificates exist"""
    print("\n🔍 Checking SSL certificates...")
    cert_path = Path('cert.pem')
    key_path = Path('key.pem')
    
    if cert_path.exists() and key_path.exists():
        print("✅ SSL certificates found")
        return True
    else:
        print("⚠️ SSL certificates not found")
        print("💡 Server will need to run on HTTP for testing")
        return False

def check_file_structure():
    """Check required file structure"""
    print("\n🔍 Checking file structure...")
    
    required_files = [
        'api.py',
        'tools/__init__.py',
        'tools/db.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing required files: {missing_files}")
        return False
    else:
        print("✅ All required files found")
        return True

async def test_middleware_chain():
    """Test middleware chain"""
    print("\n🔍 Testing middleware chain...")
    try:
        from aiohttp import web
        from aiohttp.test_utils import make_mocked_request
        
        # Import the API module
        if Path('api_fixed.py').exists():
            import api_fixed as api
        else:
            import api
        
        # Create a mock request
        request = make_mocked_request('GET', '/api/v1/csrf-token')
        
        # Test each middleware individually
        middlewares = [
            ('CORS', api.cors_handler),
            ('Error Handling', api.error_handling_middleware),
            ('CSRF Protection', api.csrf_protection),
            ('Auth', api.auth_middleware)
        ]
        
        for name, middleware in middlewares:
            try:
                # Mock handler that returns a simple response
                async def mock_handler(req):
                    return web.json_response({"test": "ok"})
                
                # Test the middleware
                response = await middleware(request, mock_handler)
                
                if hasattr(response, 'status'):
                    print(f"✅ {name} middleware working")
                else:
                    print(f"❌ {name} middleware returned non-response: {type(response)}")
                    
            except Exception as e:
                print(f"❌ {name} middleware error: {e}")
                print(f"📋 Traceback:\n{traceback.format_exc()}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Middleware chain test error: {e}")
        print(f"📋 Full traceback:\n{traceback.format_exc()}")
        return False

def create_minimal_db_module():
    """Create a minimal database module for testing"""
    print("\n🔧 Creating minimal database module...")
    
    tools_dir = Path('tools')
    tools_dir.mkdir(exist_ok=True)
    
    # Create __init__.py
    init_file = tools_dir / '__init__.py'
    init_file.write_text('# Tools package\n')
    
    # Create minimal db.py
    db_file = tools_dir / 'db.py'
    minimal_db_content = '''"""
Minimal database module for testing
"""

import uuid
import asyncio
from typing import Dict, List, Optional, Any

# In-memory storage for testing
users = {}
sessions = {}
posts = {}
comments = {}
files = {}

async def init_database():
    """Initialize database"""
    print("Database initialized (minimal version)")
    return True

async def get_session(token: str) -> Optional[Dict]:
    """Get session by token"""
    return sessions.get(token)

async def create_session(user_id: str) -> str:
    """Create new session"""
    token = str(uuid.uuid4())
    sessions[token] = {
        "user_id": user_id,
        "username": f"user_{user_id[:8]}",
        "email": f"user_{user_id[:8]}@example.com",
        "role": "user"
    }
    return token

async def delete_session(token: str) -> bool:
    """Delete session"""
    if token in sessions:
        del sessions[token]
        return True
    return False

async def cleanup_expired_sessions():
    """Cleanup expired sessions"""
    pass  # No-op for testing

async def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email"""
    for user in users.values():
        if user.get('email') == email:
            return user
    return None

async def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username"""
    for user in users.values():
        if user.get('username') == username:
            return user
    return None

async def create_user(username: str, email: str, password: str) -> str:
    """Create new user"""
    user_id = str(uuid.uuid4())
    users[user_id] = {
        "id": user_id,
        "username": username,
        "email": email,
        "password": password,  # In real app, this would be hashed
        "role": "user"
    }
    return user_id

async def authenticate_user(email: str, password: str) -> Optional[Dict]:
    """Authenticate user"""
    for user in users.values():
        if user.get('email') == email and user.get('password') == password:
            return user
    return None

async def create_post(user_id: str, title: str, content: str, status: str, tags: str) -> str:
    """Create new post"""
    post_id = str(uuid.uuid4())
    posts[post_id] = {
        "id": post_id,
        "user_id": user_id,
        "title": title,
        "content": content,
        "status": status,
        "tags": tags,
        "created_at": "2025-01-01T00:00:00Z"
    }
    return post_id

async def get_post_by_id(post_id: str) -> Optional[Dict]:
    """Get post by ID"""
    return posts.get(post_id)

async def get_published_posts_paginated(limit: int, offset: int) -> tuple:
    """Get paginated published posts"""
    published = [p for p in posts.values() if p.get('status') == 'published']
    total = len(published)
    paginated = published[offset:offset + limit]
    return paginated, total

async def get_posts_by_author(user_id: str, status: str = None) -> List[Dict]:
    """Get posts by author"""
    user_posts = [p for p in posts.values() if p.get('user_id') == user_id]
    if status:
        user_posts = [p for p in user_posts if p.get('status') == status]
    return user_posts

async def update_post(post_id: str, **kwargs) -> bool:
    """Update post"""
    if post_id in posts:
        posts[post_id].update(kwargs)
        return True
    return False

async def delete_post(post_id: str) -> bool:
    """Delete post"""
    if post_id in posts:
        del posts[post_id]
        return True
    return False

async def search_posts(query: str, limit: int) -> List[Dict]:
    """Search posts"""
    results = []
    for post in posts.values():
        if query.lower() in post.get('title', '').lower() or query.lower() in post.get('content', '').lower():
            results.append(post)
    return results[:limit]

async def create_comment(post_id: str, user_id: str, content: str) -> str:
    """Create comment"""
    comment_id = str(uuid.uuid4())
    comments[comment_id] = {
        "id": comment_id,
        "post_id": post_id,
        "user_id": user_id,
        "content": content,
        "created_at": "2025-01-01T00:00:00Z"
    }
    return comment_id

async def get_post_comments(post_id: str) -> List[Dict]:
    """Get comments for post"""
    return [c for c in comments.values() if c.get('post_id') == post_id]

async def update_comment(comment_id: str, content: str) -> bool:
    """Update comment"""
    if comment_id in comments:
        comments[comment_id]['content'] = content
        return True
    return False

async def delete_comment(comment_id: str) -> bool:
    """Delete comment"""
    if comment_id in comments:
        del comments[comment_id]
        return True
    return False

async def create_file(user_id: str, filename: str, path: str, size: int, mime_type: str) -> str:
    """Create file record"""
    file_id = str(uuid.uuid4())
    files[file_id] = {
        "id": file_id,
        "user_id": user_id,
        "name": filename,
        "path": path,
        "size": size,
        "mime_type": mime_type,
        "created_at": "2025-01-01T00:00:00Z"
    }
    return file_id

async def get_file_by_id(file_id: str) -> Optional[Dict]:
    """Get file by ID"""
    return files.get(file_id)

async def get_user_files(user_id: str) -> List[Dict]:
    """Get files by user"""
    return [f for f in files.values() if f.get('user_id') == user_id]

async def delete_file(file_id: str) -> bool:
    """Delete file record"""
    if file_id in files:
        del files[file_id]
        return True
    return False

async def get_database_stats() -> Dict:
    """Get database statistics"""
    return {
        "users": len(users),
        "posts": len(posts),
        "comments": len(comments),
        "files": len(files),
        "sessions": len(sessions)
    }

async def get_all_users_paginated(limit: int, offset: int) -> tuple:
    """Get paginated users"""
    user_list = list(users.values())
    total = len(user_list)
    paginated = user_list[offset:offset + limit]
    return paginated, total

async def get_user_activity(user_id: str) -> Dict:
    """Get user activity"""
    user_posts = len([p for p in posts.values() if p.get('user_id') == user_id])
    user_comments = len([c for c in comments.values() if c.get('user_id') == user_id])
    user_files = len([f for f in files.values() if f.get('user_id') == user_id])
    
    return {
        "posts": user_posts,
        "comments": user_comments,
        "files": user_files
    }
'''
    
    db_file.write_text(minimal_db_content)
    print("✅ Created minimal database module")
    print(f"📁 Created: {db_file}")

async def main():
    """Main debug function"""
    print("🚀 API Server Debug Script")
    print("=" * 50)
    
    # Check file structure
    file_structure_ok = check_file_structure()
    
    # If database module is missing, create minimal version
    if not Path('tools/db.py').exists():
        print("\n⚠️ Database module not found. Creating minimal version for testing...")
        create_minimal_db_module()
    
    # Test database import and initialization
    db_ok = await test_database_import()
    
    # Check SSL certificates
    ssl_ok = check_ssl_certificates()
    
    # Test basic handlers
    handlers_ok = await test_basic_handlers()
    
    # Test CSRF token handler specifically
    csrf_ok = await test_csrf_token_handler()
    
    # Test middleware chain
    middleware_ok = await test_middleware_chain()
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 DEBUG SUMMARY:")
    print(f"   File Structure: {'✅' if file_structure_ok else '❌'}")
    print(f"   Database: {'✅' if db_ok else '❌'}")
    print(f"   SSL Certificates: {'✅' if ssl_ok else '⚠️'}")
    print(f"   Basic Handlers: {'✅' if handlers_ok else '❌'}")
    print(f"   CSRF Handler: {'✅' if csrf_ok else '❌'}")
    print(f"   Middleware Chain: {'✅' if middleware_ok else '❌'}")
    
    all_ok = all([file_structure_ok, db_ok, handlers_ok, csrf_ok, middleware_ok])
    
    if all_ok:
        print("\n✅ All tests passed! The API server should work correctly.")
        if not ssl_ok:
            print("💡 Recommendation: Use HTTP (port 8080) for testing since SSL certificates are missing")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        
    print("\n🔧 Next steps:")
    if not ssl_ok:
        print("   1. Either create SSL certificates or modify the server to run on HTTP")
    print("   2. Use the fixed API server (api_fixed.py)")
    print("   3. Run the test client to verify functionality")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Debug interrupted by user")
    except Exception as e:
        print(f"\n💥 Debug script error: {e}")
        print(f"📋 Full traceback:\n{traceback.format_exc()}")
