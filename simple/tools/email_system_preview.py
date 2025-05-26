"""
Email System Implementation Preview
This would add email sending capabilities to your API
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import secrets
import asyncio
from datetime import datetime, timedelta

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',  # or your SMTP server
    'smtp_port': 587,
    'username': 'your-email@gmail.com',
    'password': 'your-app-password',  # Use app passwords for Gmail
    'from_email': 'your-email@gmail.com',
    'from_name': 'Your Blog Platform'
}

# ========================================
# EMAIL TEMPLATES
# ========================================

def get_welcome_email_template(username: str, verification_url: str) -> dict:
    """Welcome email with verification link"""
    subject = "Welcome to Our Blog Platform!"
    
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px;">
          <h1 style="color: #333;">Welcome, {username}!</h1>
          <p>Thanks for joining our blog platform. Please verify your email address to complete your registration.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_url}" 
               style="background-color: #007bff; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">
            If the button doesn't work, copy and paste this link:<br>
            <a href="{verification_url}">{verification_url}</a>
          </p>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            This verification link expires in 24 hours.
          </p>
        </div>
      </body>
    </html>
    """
    
    text_body = f"""
    Welcome, {username}!
    
    Thanks for joining our blog platform. Please verify your email address by visiting:
    {verification_url}
    
    This verification link expires in 24 hours.
    """
    
    return {
        'subject': subject,
        'html_body': html_body,
        'text_body': text_body
    }

def get_password_reset_template(username: str, reset_url: str) -> dict:
    """Password reset email template"""
    subject = "Reset Your Password"
    
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px;">
          <h1 style="color: #333;">Password Reset Request</h1>
          <p>Hi {username},</p>
          <p>You requested to reset your password. Click the button below to create a new password:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" 
               style="background-color: #dc3545; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">
            If you didn't request this, you can safely ignore this email.
          </p>
          
          <p style="color: #666; font-size: 12px;">
            This reset link expires in 1 hour.
          </p>
        </div>
      </body>
    </html>
    """
    
    text_body = f"""
    Hi {username},
    
    You requested to reset your password. Visit this link to create a new password:
    {reset_url}
    
    If you didn't request this, you can safely ignore this email.
    This reset link expires in 1 hour.
    """
    
    return {
        'subject': subject,
        'html_body': html_body,
        'text_body': text_body
    }

# ========================================
# EMAIL SENDING FUNCTIONS
# ========================================

async def send_email(to_email: str, subject: str, html_body: str, text_body: str) -> bool:
    """Send email via SMTP"""
    try:
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{EMAIL_CONFIG['from_name']} <{EMAIL_CONFIG['from_email']}>"
        message["To"] = to_email
        
        # Add both text and HTML parts
        text_part = MIMEText(text_body, "plain")
        html_part = MIMEText(html_body, "html")
        
        message.attach(text_part)
        message.attach(html_part)
        
        # Send email
        context = ssl.create_default_context()
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls(context=context)
            server.login(EMAIL_CONFIG['username'], EMAIL_CONFIG['password'])
            server.sendmail(EMAIL_CONFIG['from_email'], to_email, message.as_string())
        
        return True
        
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

async def send_welcome_email(user_email: str, username: str, user_id: str) -> bool:
    """Send welcome email with verification link"""
    # Generate verification token
    verification_token = secrets.token_urlsafe(32)
    
    # Store verification token in database (you'd add this table)
    await store_verification_token(user_id, verification_token)
    
    # Create verification URL
    verification_url = f"https://yourdomain.com/verify-email?token={verification_token}"
    
    # Get email template
    template = get_welcome_email_template(username, verification_url)
    
    # Send email
    return await send_email(
        user_email, 
        template['subject'], 
        template['html_body'], 
        template['text_body']
    )

async def send_password_reset_email(user_email: str, username: str, user_id: str) -> bool:
    """Send password reset email"""
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    
    # Store reset token with 1-hour expiration
    await store_password_reset_token(user_id, reset_token)
    
    # Create reset URL
    reset_url = f"https://yourdomain.com/reset-password?token={reset_token}"
    
    # Get email template
    template = get_password_reset_template(username, reset_url)
    
    # Send email
    return await send_email(
        user_email, 
        template['subject'], 
        template['html_body'], 
        template['text_body']
    )

# ========================================
# DATABASE FUNCTIONS FOR EMAIL FEATURES
# ========================================

async def store_verification_token(user_id: str, token: str) -> None:
    """Store email verification token"""
    expires_at = datetime.now() + timedelta(hours=24)
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO email_verifications 
            (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, token, expires_at.isoformat(), datetime.now().isoformat()))
        await db.commit()

async def store_password_reset_token(user_id: str, token: str) -> None:
    """Store password reset token"""
    expires_at = datetime.now() + timedelta(hours=1)
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO password_resets 
            (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, token, expires_at.isoformat(), datetime.now().isoformat()))
        await db.commit()

# ========================================
# NEW API ENDPOINTS
# ========================================

async def request_password_reset(request):
    """Request password reset via email"""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON data")
    
    email = validate_email(data.get("email"))
    
    # Find user
    user = await db.get_user_by_email(email)
    if not user:
        # Don't reveal if email exists or not
        return web.json_response({
            "message": "If this email is registered, you'll receive reset instructions",
            "status": "success"
        })
    
    # Send reset email
    success = await send_password_reset_email(user['email'], user['username'], user['id'])
    
    return web.json_response({
        "message": "If this email is registered, you'll receive reset instructions",
        "status": "success"
    })

async def verify_email(request):
    """Verify email address with token"""
    token = request.query.get('token')
    if not token:
        raise ValidationError("Verification token required")
    
    # Verify token and mark email as verified
    user_id = await verify_email_token(token)
    if not user_id:
        return web.json_response({
            "message": "Invalid or expired verification token",
            "status": "error"
        }, status=400)
    
    # Mark email as verified
    await mark_email_verified(user_id)
    
    return web.json_response({
        "message": "Email verified successfully",
        "status": "success"
    })

# ========================================
# ENHANCED REGISTRATION WITH EMAIL
# ========================================

async def register_user_with_email(request):
    """Enhanced registration that sends welcome email"""
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
    
    # Send welcome email
    email_sent = await send_welcome_email(email, username, user_id)
    
    return web.json_response({
        "message": "User registered successfully. Please check your email to verify your account.",
        "user_id": user_id,
        "email_sent": email_sent,
        "status": "success"
    })

"""
ADDITIONAL DATABASE TABLES NEEDED:

CREATE TABLE email_verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP NULL;

NEW API ENDPOINTS:
POST /api/v1/auth/request-password-reset
GET  /api/v1/auth/verify-email?token=TOKEN
POST /api/v1/auth/reset-password
"""