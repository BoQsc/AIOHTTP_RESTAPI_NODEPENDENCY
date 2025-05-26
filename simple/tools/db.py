"""
Database module - All SQL statements and database logic
Provides clean API for the main application
"""

import aiosqlite
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Database configuration
DB_PATH = "api.db"

# ========================================
# DATABASE INITIALIZATION
# ========================================

async def init_database():
    """Initialize all database tables"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Users table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sessions table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Posts table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id TEXT PRIMARY KEY,
                author_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'draft',
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users (id)
            )
        """)
        
        # Comments table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                post_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                FOREIGN KEY (author_id) REFERENCES users (id)
            )
        """)
        
        # Files table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                uploader_id TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER,
                type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users (id)
            )
        """)
        
        # Create indexes for performance
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id)")
        
        await db.commit()

# ========================================
# USER FUNCTIONS
# ========================================

async def create_user(username: str, email: str, password: str, role: str = "user") -> str:
    """Create new user"""
    user_id = str(uuid.uuid4())
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO users (id, username, email, password_hash, role)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, username, email, password_hash, role))
        await db.commit()
    
    return user_id

async def get_user_by_id(user_id: str) -> Optional[Dict]:
    """Get user by ID"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def update_user(user_id: str, **kwargs) -> bool:
    """Update user fields"""
    if not kwargs:
        return False
    
    # Build dynamic UPDATE query
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [datetime.now().isoformat(), user_id]
    
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(f"""
            UPDATE users SET {fields}, updated_at = ? WHERE id = ?
        """, values)
        await db.commit()
        return cursor.rowcount > 0

async def delete_user(user_id: str) -> bool:
    """Delete user and related data"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Delete in order due to foreign keys
        await db.execute("DELETE FROM comments WHERE author_id = ?", (user_id,))
        await db.execute("DELETE FROM posts WHERE author_id = ?", (user_id,))
        await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM files WHERE uploader_id = ?", (user_id,))
        cursor = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
        return cursor.rowcount > 0

async def get_all_users() -> List[Dict]:
    """Get all users"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# ========================================
# SESSION FUNCTIONS
# ========================================

async def create_session(user_id: str, expires_hours: int = 24) -> str:
    """Create user session"""
    session_id = str(uuid.uuid4())
    token = hashlib.sha256(f"{user_id}{datetime.now()}".encode()).hexdigest()
    expires_at = datetime.now() + timedelta(hours=expires_hours)
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO sessions (id, user_id, token, expires_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, user_id, token, expires_at.isoformat()))
        await db.commit()
    
    return token

async def get_session(token: str) -> Optional[Dict]:
    """Get session by token"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT s.*, u.username, u.email, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > datetime('now')
        """, (token,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def delete_session(token: str) -> bool:
    """Delete session (logout)"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await db.commit()
        return cursor.rowcount > 0

async def cleanup_expired_sessions() -> int:
    """Remove expired sessions"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
        await db.commit()
        return cursor.rowcount

async def get_user_sessions(user_id: str) -> List[Dict]:
    """Get all active sessions for user"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM sessions 
            WHERE user_id = ? AND expires_at > datetime('now')
            ORDER BY created_at DESC
        """, (user_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# ========================================
# POST FUNCTIONS
# ========================================

async def create_post(author_id: str, title: str, content: str, status: str = "draft", tags: str = "") -> str:
    """Create new post"""
    post_id = str(uuid.uuid4())
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO posts (id, author_id, title, content, status, tags)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (post_id, author_id, title, content, status, tags))
        await db.commit()
    
    return post_id

async def get_post_by_id(post_id: str) -> Optional[Dict]:
    """Get post by ID with author info"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT p.*, u.username as author_username, u.email as author_email
            FROM posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.id = ?
        """, (post_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_posts_by_author(author_id: str, status: str = None) -> List[Dict]:
    """Get posts by author"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        if status:
            query = """
                SELECT p.*, u.username as author_username,
                       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
                FROM posts p
                JOIN users u ON p.author_id = u.id
                WHERE p.author_id = ? AND p.status = ?
                ORDER BY p.created_at DESC
            """
            params = (author_id, status)
        else:
            query = """
                SELECT p.*, u.username as author_username,
                       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
                FROM posts p
                JOIN users u ON p.author_id = u.id
                WHERE p.author_id = ?
                ORDER BY p.created_at DESC
            """
            params = (author_id,)
        
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_published_posts(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Get published posts with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT p.*, u.username as author_username,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
            FROM posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.status = 'published'
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def update_post(post_id: str, **kwargs) -> bool:
    """Update post fields"""
    if not kwargs:
        return False
    
    # Build dynamic UPDATE query
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [datetime.now().isoformat(), post_id]
    
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(f"""
            UPDATE posts SET {fields}, updated_at = ? WHERE id = ?
        """, values)
        await db.commit()
        return cursor.rowcount > 0

async def delete_post(post_id: str) -> bool:
    """Delete post and related comments"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
        cursor = await db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        await db.commit()
        return cursor.rowcount > 0

async def search_posts(query: str, limit: int = 50) -> List[Dict]:
    """Search posts by title, content, or tags"""
    search_term = f"%{query}%"
    
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT p.*, u.username as author_username,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
            FROM posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.status = 'published' 
            AND (p.title LIKE ? OR p.content LIKE ? OR p.tags LIKE ?)
            ORDER BY p.created_at DESC
            LIMIT ?
        """, (search_term, search_term, search_term, limit)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# ========================================
# COMMENT FUNCTIONS
# ========================================

async def create_comment(post_id: str, author_id: str, content: str) -> str:
    """Create new comment"""
    comment_id = str(uuid.uuid4())
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO comments (id, post_id, author_id, content)
            VALUES (?, ?, ?, ?)
        """, (comment_id, post_id, author_id, content))
        await db.commit()
    
    return comment_id

async def get_post_comments(post_id: str) -> List[Dict]:
    """Get all comments for a post"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT c.*, u.username as author_username
            FROM comments c
            JOIN users u ON c.author_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        """, (post_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_user_comments(author_id: str) -> List[Dict]:
    """Get all comments by user"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT c.*, p.title as post_title
            FROM comments c
            JOIN posts p ON c.post_id = p.id
            WHERE c.author_id = ?
            ORDER BY c.created_at DESC
        """, (author_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def update_comment(comment_id: str, content: str) -> bool:
    """Update comment content"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            UPDATE comments SET content = ? WHERE id = ?
        """, (content, comment_id))
        await db.commit()
        return cursor.rowcount > 0

async def delete_comment(comment_id: str) -> bool:
    """Delete comment"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        await db.commit()
        return cursor.rowcount > 0

# ========================================
# FILE FUNCTIONS
# ========================================

async def create_file(uploader_id: str, name: str, path: str, size: int, file_type: str = None) -> str:
    """Create file record"""
    file_id = str(uuid.uuid4())
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO files (id, uploader_id, name, path, size, type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (file_id, uploader_id, name, path, size, file_type))
        await db.commit()
    
    return file_id

async def get_file_by_id(file_id: str) -> Optional[Dict]:
    """Get file by ID"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT f.*, u.username as uploader_username
            FROM files f
            JOIN users u ON f.uploader_id = u.id
            WHERE f.id = ?
        """, (file_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_user_files(uploader_id: str) -> List[Dict]:
    """Get files uploaded by user"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM files 
            WHERE uploader_id = ?
            ORDER BY created_at DESC
        """, (uploader_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_all_files(limit: int = 100, offset: int = 0) -> List[Dict]:
    """Get all files with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT f.*, u.username as uploader_username
            FROM files f
            JOIN users u ON f.uploader_id = u.id
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def delete_file(file_id: str) -> bool:
    """Delete file record"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
        return cursor.rowcount > 0

# ========================================
# ANALYTICS & STATS FUNCTIONS
# ========================================

async def get_database_stats() -> Dict:
    """Get comprehensive database statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        stats = {}
        
        # User stats
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            stats["total_users"] = (await cursor.fetchone())[0]
        
        # Post stats
        async with db.execute("SELECT status, COUNT(*) FROM posts GROUP BY status") as cursor:
            post_stats = await cursor.fetchall()
            stats["posts_by_status"] = {row[0]: row[1] for row in post_stats}
        
        # Comment stats
        async with db.execute("SELECT COUNT(*) FROM comments") as cursor:
            stats["total_comments"] = (await cursor.fetchone())[0]
        
        # File stats
        async with db.execute("SELECT COUNT(*), SUM(size) FROM files") as cursor:
            file_row = await cursor.fetchone()
            stats["total_files"] = file_row[0]
            stats["total_file_size"] = file_row[1] or 0
        
        # Recent activity (last 7 days)
        async with db.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM posts 
            WHERE created_at > date('now', '-7 days')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        """) as cursor:
            recent_posts = await cursor.fetchall()
            stats["recent_posts"] = [{"date": row[0], "count": row[1]} for row in recent_posts]
        
        return stats

async def get_user_activity(user_id: str) -> Dict:
    """Get user activity statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        activity = {}
        
        # Post count
        async with db.execute("SELECT COUNT(*) FROM posts WHERE author_id = ?", (user_id,)) as cursor:
            activity["post_count"] = (await cursor.fetchone())[0]
        
        # Comment count
        async with db.execute("SELECT COUNT(*) FROM comments WHERE author_id = ?", (user_id,)) as cursor:
            activity["comment_count"] = (await cursor.fetchone())[0]
        
        # File count
        async with db.execute("SELECT COUNT(*) FROM files WHERE uploader_id = ?", (user_id,)) as cursor:
            activity["file_count"] = (await cursor.fetchone())[0]
        
        return activity

# ========================================
# UTILITY FUNCTIONS
# ========================================

async def execute_raw_query(sql: str, *params) -> List[Dict]:
    """Execute raw SQL query and return results"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def execute_raw_command(sql: str, *params) -> int:
    """Execute raw SQL command and return affected rows"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount

# ========================================
# AUTHENTICATION HELPERS
# ========================================

def hash_password(password: str) -> str:
    """Hash password"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash

async def authenticate_user(email: str, password: str) -> Optional[Dict]:
    """Authenticate user and return user info"""
    user = await get_user_by_email(email)
    if user and verify_password(password, user["password_hash"]):
        # Remove password hash from returned data
        user_safe = user.copy()
        del user_safe["password_hash"]
        return user_safe
    return None