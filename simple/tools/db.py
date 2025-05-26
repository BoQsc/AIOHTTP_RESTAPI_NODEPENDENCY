"""
Enhanced Database module - All SQL statements and database logic with pagination support
Provides clean API for the main application
"""

import aiosqlite
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

# Database configuration
DB_PATH = "api.db"

# ========================================
# DATABASE INITIALIZATION
# ========================================

async def init_database():
    """Initialize all database tables with enhanced indexes"""
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
                status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
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
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
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
                size INTEGER DEFAULT 0,
                type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users (id)
            )
        """)
        
        # Create comprehensive indexes for performance
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)")
        
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_status_created ON posts(status, created_at)")
        
        await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at)")
        
        await db.execute("CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at)")
        
        # Full-text search for posts (SQLite FTS5)
        await db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
                id UNINDEXED,
                title,
                content,
                tags,
                content='posts',
                content_rowid='rowid'
            )
        """)
        
        # Trigger to keep FTS table in sync
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_insert AFTER INSERT ON posts BEGIN
                INSERT INTO posts_fts(id, title, content, tags) 
                VALUES (new.id, new.title, new.content, new.tags);
            END
        """)
        
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_delete AFTER DELETE ON posts BEGIN
                DELETE FROM posts_fts WHERE id = old.id;
            END
        """)
        
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_update AFTER UPDATE ON posts BEGIN
                DELETE FROM posts_fts WHERE id = old.id;
                INSERT INTO posts_fts(id, title, content, tags) 
                VALUES (new.id, new.title, new.content, new.tags);
            END
        """)
        
        await db.commit()

# ========================================
# USER FUNCTIONS (ENHANCED)
# ========================================

async def create_user(username: str, email: str, password: str, role: str = "user") -> str:
    """Create new user with enhanced validation"""
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
    """Get all users (legacy function)"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT id, username, email, role, created_at 
            FROM users 
            ORDER BY created_at DESC
        """) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_all_users_paginated(limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """Get all users with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total count
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
        async with db.execute("""
            SELECT id, username, email, role, created_at 
            FROM users 
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)) as cursor:
            rows = await cursor.fetchall()
            users = [dict(row) for row in rows]
        
        return users, total_count

# ========================================
# SESSION FUNCTIONS (ENHANCED)
# ========================================

async def create_session(user_id: str, expires_hours: int = 24) -> str:
    """Create user session"""
    session_id = str(uuid.uuid4())
    token = hashlib.sha256(f"{user_id}{datetime.now()}{session_id}".encode()).hexdigest()
    expires_at = datetime.now() + timedelta(hours=expires_hours)
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO sessions (id, user_id, token, expires_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, user_id, token, expires_at.isoformat()))
        await db.commit()
    
    return token

async def get_session(token: str) -> Optional[Dict]:
    """Get session by token with user info"""
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
# POST FUNCTIONS (ENHANCED)
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
    """Get published posts with pagination (legacy)"""
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

async def get_published_posts_paginated(limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """Get published posts with pagination and total count"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total count of published posts
        async with db.execute("""
            SELECT COUNT(*) FROM posts WHERE status = 'published'
        """) as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
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
            posts = [dict(row) for row in rows]
        
        return posts, total_count

async def get_all_posts_paginated(limit: int = 50, offset: int = 0, status: str = None) -> Tuple[List[Dict], int]:
    """Get all posts with optional status filter"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        if status:
            count_query = "SELECT COUNT(*) FROM posts WHERE status = ?"
            params = (status,)
            select_query = """
                SELECT p.*, u.username as author_username,
                       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
                FROM posts p
                JOIN users u ON p.author_id = u.id
                WHERE p.status = ?
                ORDER BY p.created_at DESC
                LIMIT ? OFFSET ?
            """
            select_params = (status, limit, offset)
        else:
            count_query = "SELECT COUNT(*) FROM posts"
            params = ()
            select_query = """
                SELECT p.*, u.username as author_username,
                       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
                FROM posts p
                JOIN users u ON p.author_id = u.id
                ORDER BY p.created_at DESC
                LIMIT ? OFFSET ?
            """
            select_params = (limit, offset)
        
        # Get total count
        async with db.execute(count_query, params) as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
        async with db.execute(select_query, select_params) as cursor:
            rows = await cursor.fetchall()
            posts = [dict(row) for row in rows]
        
        return posts, total_count

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
        # Comments will be cascade deleted due to foreign key constraint
        cursor = await db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        await db.commit()
        return cursor.rowcount > 0

async def search_posts(query: str, limit: int = 50) -> List[Dict]:
    """Search posts using FTS5 full-text search"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Use FTS5 for better search performance
        async with db.execute("""
            SELECT p.*, u.username as author_username,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count,
                   posts_fts.rank
            FROM posts_fts
            JOIN posts p ON posts_fts.id = p.id
            JOIN users u ON p.author_id = u.id
            WHERE posts_fts MATCH ? AND p.status = 'published'
            ORDER BY posts_fts.rank
            LIMIT ?
        """, (query, limit)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_popular_posts(days: int = 7, limit: int = 10) -> List[Dict]:
    """Get posts with most comments in recent days"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT p.*, u.username as author_username,
                   COUNT(c.id) as comment_count
            FROM posts p
            JOIN users u ON p.author_id = u.id
            LEFT JOIN comments c ON p.id = c.post_id 
                AND c.created_at > date('now', '-' || ? || ' days')
            WHERE p.status = 'published'
            GROUP BY p.id
            ORDER BY comment_count DESC, p.created_at DESC
            LIMIT ?
        """, (days, limit)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# ========================================
# COMMENT FUNCTIONS (ENHANCED)
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

async def get_post_comments_paginated(post_id: str, limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """Get comments for a post with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total count
        async with db.execute("""
            SELECT COUNT(*) FROM comments WHERE post_id = ?
        """, (post_id,)) as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
        async with db.execute("""
            SELECT c.*, u.username as author_username
            FROM comments c
            JOIN users u ON c.author_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
            LIMIT ? OFFSET ?
        """, (post_id, limit, offset)) as cursor:
            rows = await cursor.fetchall()
            comments = [dict(row) for row in rows]
        
        return comments, total_count

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
# FILE FUNCTIONS (ENHANCED)
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

async def get_user_files_paginated(uploader_id: str, limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """Get files uploaded by user with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total count
        async with db.execute("""
            SELECT COUNT(*) FROM files WHERE uploader_id = ?
        """, (uploader_id,)) as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
        async with db.execute("""
            SELECT * FROM files 
            WHERE uploader_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (uploader_id, limit, offset)) as cursor:
            rows = await cursor.fetchall()
            files = [dict(row) for row in rows]
        
        return files, total_count

async def get_all_files(limit: int = 100, offset: int = 0) -> List[Dict]:
    """Get all files with pagination (legacy)"""
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

async def get_all_files_paginated(limit: int = 100, offset: int = 0) -> Tuple[List[Dict], int]:
    """Get all files with pagination and total count"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total count
        async with db.execute("SELECT COUNT(*) FROM files") as cursor:
            total_count = (await cursor.fetchone())[0]
        
        # Get paginated results
        async with db.execute("""
            SELECT f.*, u.username as uploader_username
            FROM files f
            JOIN users u ON f.uploader_id = u.id
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)) as cursor:
            rows = await cursor.fetchall()
            files = [dict(row) for row in rows]
        
        return files, total_count

async def delete_file(file_id: str) -> bool:
    """Delete file record"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
        return cursor.rowcount > 0

# ========================================
# ANALYTICS & STATS FUNCTIONS (ENHANCED)
# ========================================

async def get_database_stats() -> Dict:
    """Get comprehensive database statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        stats = {}
        
        # User stats
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            stats["total_users"] = (await cursor.fetchone())[0]
        
        async with db.execute("SELECT role, COUNT(*) FROM users GROUP BY role") as cursor:
            role_stats = await cursor.fetchall()
            stats["users_by_role"] = {row[0]: row[1] for row in role_stats}
        
        # Post stats
        async with db.execute("SELECT status, COUNT(*) FROM posts GROUP BY status") as cursor:
            post_stats = await cursor.fetchall()
            stats["posts_by_status"] = {row[0]: row[1] for row in post_stats}
        
        async with db.execute("SELECT COUNT(*) FROM posts") as cursor:
            stats["total_posts"] = (await cursor.fetchone())[0]
        
        # Comment stats
        async with db.execute("SELECT COUNT(*) FROM comments") as cursor:
            stats["total_comments"] = (await cursor.fetchone())[0]
        
        # File stats
        async with db.execute("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files") as cursor:
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
        
        # Active sessions
        async with db.execute("""
            SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')
        """) as cursor:
            stats["active_sessions"] = (await cursor.fetchone())[0]
        
        return stats

async def get_user_activity(user_id: str) -> Dict:
    """Get user activity statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        activity = {"user_id": user_id}
        
        # Post count by status
        async with db.execute("""
            SELECT status, COUNT(*) FROM posts WHERE author_id = ? GROUP BY status
        """, (user_id,)) as cursor:
            post_stats = await cursor.fetchall()
            activity["posts_by_status"] = {row[0]: row[1] for row in post_stats}
        
        # Total posts
        async with db.execute("SELECT COUNT(*) FROM posts WHERE author_id = ?", (user_id,)) as cursor:
            activity["total_posts"] = (await cursor.fetchone())[0]
        
        # Comment count
        async with db.execute("SELECT COUNT(*) FROM comments WHERE author_id = ?", (user_id,)) as cursor:
            activity["total_comments"] = (await cursor.fetchone())[0]
        
        # File count and size
        async with db.execute("""
            SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files WHERE uploader_id = ?
        """, (user_id,)) as cursor:
            file_row = await cursor.fetchone()
            activity["total_files"] = file_row[0]
            activity["total_file_size"] = file_row[1] or 0
        
        # Recent activity (last 30 days)
        async with db.execute("""
            SELECT 
                (SELECT COUNT(*) FROM posts WHERE author_id = ? AND created_at > date('now', '-30 days')) as recent_posts,
                (SELECT COUNT(*) FROM comments WHERE author_id = ? AND created_at > date('now', '-30 days')) as recent_comments
        """, (user_id, user_id)) as cursor:
            recent = await cursor.fetchone()
            activity["recent_posts"] = recent[0]
            activity["recent_comments"] = recent[1]
        
        return activity

async def get_trending_tags(limit: int = 20, days: int = 30) -> List[Dict]:
    """Get trending tags from recent posts"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT tags FROM posts 
            WHERE status = 'published' 
            AND created_at > date('now', '-' || ? || ' days')
            AND tags IS NOT NULL AND tags != ''
        """, (days,)) as cursor:
            rows = await cursor.fetchall()
            
            # Parse tags and count occurrences
            tag_counts = {}
            for row in rows:
                tags = row['tags'].split(',')
                for tag in tags:
                    tag = tag.strip().lower()
                    if tag:
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            # Sort by count and return top tags
            sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
            return [{"tag": tag, "count": count} for tag, count in sorted_tags]

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

async def vacuum_database() -> None:
    """Optimize database performance"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("VACUUM")
        await db.execute("ANALYZE")
        await db.commit()

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

# ========================================
# DATABASE HEALTH CHECKS
# ========================================

async def check_database_health() -> Dict:
    """Check database health and integrity"""
    async with aiosqlite.connect(DB_PATH) as db:
        health = {}
        
        # Check if all tables exist
        async with db.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
        """) as cursor:
            tables = [row[0] for row in await cursor.fetchall()]
            expected_tables = ['users', 'sessions', 'posts', 'comments', 'files', 'posts_fts']
            health["tables_exist"] = all(table in tables for table in expected_tables)
            health["existing_tables"] = tables
        
        # Check foreign key constraints
        async with db.execute("PRAGMA foreign_key_check") as cursor:
            fk_violations = await cursor.fetchall()
            health["foreign_key_violations"] = len(fk_violations)
        
        # Check database integrity
        async with db.execute("PRAGMA integrity_check") as cursor:
            integrity = await cursor.fetchone()
            health["integrity_ok"] = integrity[0] == "ok"
        
        return health