#!/usr/bin/env python3
"""
Enhanced API Test Client with Smart Rate Limit Handling
Comprehensive testing with intelligent rate limit management
"""

import requests
import json
import time
import os
import uuid
import tempfile
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import argparse
import sys

# ========================================
# TEST CONFIGURATION
# ========================================

@dataclass
class TestConfig:
    """Enhanced test configuration with rate limit handling"""
    base_url: str = "http://localhost:8080"
    timeout: int = 30
    retry_delay: float = 1.0
    max_retries: int = 3
    log_level: str = "INFO"
    test_file_path: str = "test_upload.txt"
    
    # Rate limiting options
    respect_rate_limits: bool = True
    rate_limit_mode: str = "smart"  # "smart", "aggressive", "patient", "skip"
    max_wait_time: int = 120  # Maximum seconds to wait for rate limit reset
    request_delay: float = 0.5  # Delay between requests in patient mode
    
    def __post_init__(self):
        # Ensure base_url doesn't end with slash
        self.base_url = self.base_url.rstrip('/')

@dataclass
class TestResult:
    """Individual test result"""
    name: str
    success: bool
    duration: float
    response_code: Optional[int] = None
    message: str = ""
    data: Optional[Dict] = None
    rate_limited: bool = False
    retry_count: int = 0

@dataclass
class TestUser:
    """Test user data"""
    username: str
    email: str
    password: str
    token: Optional[str] = None
    user_id: Optional[str] = None
    role: str = "user"

# ========================================
# ENHANCED API TEST CLIENT
# ========================================

class EnhancedAPITestClient:
    """Enhanced API test client with smart rate limit handling"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.timeout
        
        # Test data storage
        self.csrf_token = None
        self.test_users: List[TestUser] = []
        self.test_posts: List[str] = []  # Post IDs
        self.test_files: List[str] = []  # File IDs
        self.test_comments: List[str] = []  # Comment IDs
        
        # Test results and stats
        self.results: List[TestResult] = []
        self.start_time = time.time()
        self.rate_limit_stats = {
            'total_rate_limited': 0,
            'total_wait_time': 0,
            'max_wait_time': 0,
            'endpoints_rate_limited': set()
        }
        
        # Setup logging
        self.setup_logging()
        
        # Create test file
        self.create_test_file()
        
        self.logger.info(f"Enhanced API Test Client initialized for {config.base_url}")
        self.logger.info(f"Rate limit mode: {config.rate_limit_mode}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('api_test_results.log', encoding='utf-8')
            ]
        )
        self.logger = logging.getLogger('EnhancedAPITestClient')
    
    def create_test_file(self):
        """Create a test file for upload tests"""
        test_content = f"""Test file for API upload testing
Created at: {datetime.now()}
UUID: {uuid.uuid4()}
This is a test file used for validating file upload functionality.
It contains some sample text content for testing purposes.
"""
        with open(self.config.test_file_path, 'w', encoding='utf-8') as f:
            f.write(test_content)
        self.logger.info(f"Created test file: {self.config.test_file_path}")
    
    def cleanup_test_file(self):
        """Clean up test file"""
        try:
            if os.path.exists(self.config.test_file_path):
                os.remove(self.config.test_file_path)
                self.logger.info("Cleaned up test file")
        except Exception as e:
            self.logger.error(f"Failed to cleanup test file: {e}")
    
    def smart_delay(self, endpoint: str = ""):
        """Apply smart delay based on rate limit mode"""
        if self.config.rate_limit_mode == "patient":
            time.sleep(self.config.request_delay)
        elif self.config.rate_limit_mode == "smart":
            # Smart delays based on endpoint sensitivity
            if any(sensitive in endpoint for sensitive in ['/auth/', '/csrf-token']):
                time.sleep(1.0)  # Longer delay for auth endpoints
            else:
                time.sleep(0.2)  # Short delay for other endpoints
    
    def handle_rate_limit(self, response: requests.Response, endpoint: str) -> Tuple[bool, int]:
        """
        Handle rate limit response intelligently
        Returns: (should_retry, wait_time)
        """
        if response.status_code != 429:
            return False, 0
        
        self.rate_limit_stats['total_rate_limited'] += 1
        self.rate_limit_stats['endpoints_rate_limited'].add(endpoint)
        
        # Parse rate limit info from response
        retry_after = None
        try:
            if response.headers.get('Retry-After'):
                retry_after = int(response.headers['Retry-After'])
            else:
                data = response.json()
                retry_after = data.get('rate_limit', {}).get('retry_after_seconds')
        except (ValueError, KeyError, json.JSONDecodeError):
            pass
        
        # Default retry after if not specified
        if not retry_after:
            retry_after = 60  # Default 1 minute
        
        # Check if we should wait based on configuration
        if self.config.rate_limit_mode == "skip":
            self.logger.info(f"Rate limited on {endpoint}, skipping due to mode setting")
            return False, 0
        
        if retry_after > self.config.max_wait_time:
            self.logger.warning(f"Rate limit wait time ({retry_after}s) exceeds max ({self.config.max_wait_time}s), skipping")
            return False, 0
        
        if self.config.rate_limit_mode in ["smart", "patient", "aggressive"]:
            wait_time = min(retry_after, self.config.max_wait_time)
            self.rate_limit_stats['total_wait_time'] += wait_time
            self.rate_limit_stats['max_wait_time'] = max(self.rate_limit_stats['max_wait_time'], wait_time)
            
            self.logger.info(f"Rate limited on {endpoint}, waiting {wait_time}s...")
            time.sleep(wait_time)
            return True, wait_time
        
        return False, 0
    
    def make_request_with_retry(self, method: str, endpoint: str, max_retries: int = None, **kwargs) -> Tuple[requests.Response, float, int]:
        """Make API request with intelligent retry logic"""
        if max_retries is None:
            max_retries = self.config.max_retries
        
        url = f"{self.config.base_url}{endpoint}"
        total_duration = 0
        retry_count = 0
        
        # Add CSRF token if needed
        if method.upper() in ['POST', 'PUT', 'DELETE'] and self.csrf_token:
            headers = kwargs.get('headers', {})
            headers['X-CSRF-Token'] = self.csrf_token
            kwargs['headers'] = headers
        
        # Apply smart delay before request
        self.smart_delay(endpoint)
        
        for attempt in range(max_retries + 1):
            start_time = time.time()
            
            try:
                response = self.session.request(method, url, **kwargs)
                duration = time.time() - start_time
                total_duration += duration
                
                # Handle rate limiting
                if response.status_code == 429:
                    should_retry, wait_time = self.handle_rate_limit(response, endpoint)
                    if should_retry and attempt < max_retries:
                        retry_count += 1
                        continue
                    else:
                        # Don't retry, return the 429 response
                        break
                
                # Success or non-retryable error
                self.logger.debug(f"{method} {endpoint} -> {response.status_code} ({duration:.3f}s, attempt {attempt + 1})")
                break
                
            except Exception as e:
                duration = time.time() - start_time
                total_duration += duration
                
                if attempt < max_retries:
                    retry_count += 1
                    self.logger.warning(f"{method} {endpoint} failed (attempt {attempt + 1}): {e}, retrying...")
                    time.sleep(self.config.retry_delay * (attempt + 1))  # Exponential backoff
                    continue
                else:
                    self.logger.error(f"{method} {endpoint} failed after {max_retries + 1} attempts: {e}")
                    raise
        
        return response, total_duration, retry_count
    
    def add_result(self, name: str, success: bool, duration: float, 
                   response_code: Optional[int] = None, message: str = "", 
                   data: Optional[Dict] = None, rate_limited: bool = False, 
                   retry_count: int = 0):
        """Add test result with enhanced tracking"""
        result = TestResult(name, success, duration, response_code, message, data, rate_limited, retry_count)
        self.results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        retry_info = f" (retries: {retry_count})" if retry_count > 0 else ""
        rate_info = " [RATE LIMITED]" if rate_limited else ""
        
        self.logger.info(f"{status} {name} ({duration:.3f}s){retry_info}{rate_info} - {message}")
        
        if not success:
            self.logger.error(f"Test failed: {name} - {message}")
    
    # ========================================
    # ENHANCED TEST METHODS
    # ========================================
    
    def test_health_check(self) -> bool:
        """Test health check endpoint"""
        try:
            response, duration, retries = self.make_request_with_retry('GET', '/api/v1/health')
            
            if response.status_code == 200:
                data = response.json()
                self.add_result("Health Check", True, duration, 200, 
                              f"Server healthy, version: {data.get('version', 'unknown')}", 
                              data, retry_count=retries)
                return True
            else:
                self.add_result("Health Check", False, duration, response.status_code, 
                              "Health check failed", retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Health Check", False, 0, None, f"Exception: {e}")
            return False
    
    def test_index(self) -> bool:
        """Test index endpoint"""
        try:
            response, duration, retries = self.make_request_with_retry('GET', '/api/v1/')
            
            if response.status_code == 200:
                data = response.json()
                features = data.get('features', [])
                self.add_result("Index", True, duration, 200, 
                              f"API info retrieved, features: {len(features)}", 
                              data, retry_count=retries)
                return True
            else:
                self.add_result("Index", False, duration, response.status_code, 
                              "Index endpoint failed", retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Index", False, 0, None, f"Exception: {e}")
            return False
    
    def test_csrf_token(self) -> bool:
        """Test CSRF token generation with rate limit awareness"""
        try:
            response, duration, retries = self.make_request_with_retry(
                'GET', '/api/v1/csrf-token', max_retries=1  # Lower retries for CSRF
            )
            
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get('csrf_token')
                if self.csrf_token:
                    self.add_result("CSRF Token", True, duration, 200, 
                                  "CSRF token obtained", 
                                  {'token_length': len(self.csrf_token)},
                                  retry_count=retries)
                    return True
                else:
                    self.add_result("CSRF Token", False, duration, 200, 
                                  "No CSRF token in response", retry_count=retries)
                    return False
            elif response.status_code == 429:
                self.add_result("CSRF Token", False, duration, 429, 
                              "Rate limited - CSRF endpoint has very low limits", 
                              rate_limited=True, retry_count=retries)
                return False
            else:
                self.add_result("CSRF Token", False, duration, response.status_code, 
                              "CSRF token request failed", retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("CSRF Token", False, 0, None, f"Exception: {e}")
            return False
    
    def test_rate_limiting_analysis(self) -> bool:
        """Analyze rate limiting behavior without overwhelming the server"""
        self.logger.info("Analyzing rate limiting behavior...")
        
        # Test with a few controlled requests
        endpoint = '/api/v1/csrf-token'
        success_count = 0
        rate_limited_count = 0
        
        for i in range(3):  # Only try 3 requests to avoid overwhelming
            try:
                response, duration, retries = self.make_request_with_retry(
                    'GET', endpoint, max_retries=0  # Don't retry for this test
                )
                
                if response.status_code == 200:
                    success_count += 1
                    self.logger.debug(f"Request {i+1}: Success")
                elif response.status_code == 429:
                    rate_limited_count += 1
                    self.logger.debug(f"Request {i+1}: Rate limited")
                    break  # Stop testing once rate limited
                    
                time.sleep(0.5)  # Small delay
                
            except Exception as e:
                self.logger.error(f"Rate limit analysis request {i+1} failed: {e}")
        
        # Analyze results
        if rate_limited_count > 0:
            self.add_result("Rate Limiting Analysis", True, 0, 429, 
                          f"Rate limiting active: {success_count} requests succeeded before limit")
            return True
        elif success_count >= 2:
            self.add_result("Rate Limiting Analysis", True, 0, 200, 
                          f"Rate limiting may be lenient: {success_count} requests succeeded")
            return True
        else:
            self.add_result("Rate Limiting Analysis", False, 0, None, 
                          f"Rate limiting analysis inconclusive")
            return False
    
    def test_user_registration(self) -> bool:
        """Test user registration with smart rate limit handling"""
        user = TestUser(
            username=f"testuser_{int(time.time())}",
            email=f"test_{int(time.time())}@example.com",
            password="testpassword123"
        )
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', '/api/v1/auth/register',
                json={
                    'username': user.username,
                    'email': user.email,
                    'password': user.password
                },
                headers={'Content-Type': 'application/json'},
                max_retries=2  # Allow more retries for registration
            )
            
            if response.status_code == 200:
                data = response.json()
                user.user_id = data.get('user_id')
                self.test_users.append(user)
                self.add_result("User Registration", True, duration, 200, 
                              f"User registered: {user.username}", data, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("User Registration", False, duration, 429, 
                              "Rate limited - registration endpoint has low limits", 
                              rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("User Registration", False, duration, response.status_code, 
                              f"Registration failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("User Registration", False, 0, None, f"Exception: {e}")
            return False
    
    def test_user_login(self) -> bool:
        """Test user login with enhanced retry logic"""
        if not self.test_users:
            self.add_result("User Login", False, 0, None, "No test users available")
            return False
        
        user = self.test_users[0]
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', '/api/v1/auth/login',
                json={
                    'email': user.email,
                    'password': user.password
                },
                headers={'Content-Type': 'application/json'},
                max_retries=2
            )
            
            if response.status_code == 200:
                data = response.json()
                user.token = data.get('token')
                user_data = data.get('user', {})
                user.role = user_data.get('role', 'user')
                
                # Set authorization header for future requests
                self.session.headers['Authorization'] = f"Bearer {user.token}"
                
                self.add_result("User Login", True, duration, 200, 
                              f"Login successful for {user.username}", data, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("User Login", False, duration, 429, 
                              "Rate limited during login", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("User Login", False, duration, response.status_code, 
                              f"Login failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("User Login", False, 0, None, f"Exception: {e}")
            return False
    
    def test_get_current_user(self) -> bool:
        """Test getting current user info"""
        if not self.test_users or not self.test_users[0].token:
            self.add_result("Get Current User", False, 0, None, "No authenticated user")
            return False
        
        try:
            response, duration, retries = self.make_request_with_retry('GET', '/api/v1/auth/me')
            
            if response.status_code == 200:
                data = response.json()
                user_info = data.get('user', {})
                self.add_result("Get Current User", True, duration, 200, 
                              f"User info retrieved: {user_info.get('username')}", 
                              data, retry_count=retries)
                return True
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Get Current User", False, duration, response.status_code, 
                              f"Failed to get user info: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Get Current User", False, 0, None, f"Exception: {e}")
            return False
    
    # ========================================
    # SMART TEST EXECUTION MODES
    # ========================================
    
    def run_basic_tests(self) -> Dict[str, Any]:
        """Run basic tests that don't require authentication"""
        self.logger.info("🔍 Running basic functionality tests...")
        
        self.test_health_check()
        self.test_index()
        
        return self.generate_report()
    
    def run_rate_limit_tests(self) -> Dict[str, Any]:
        """Run rate limiting specific tests"""
        self.logger.info("🚦 Running rate limiting tests...")
        
        self.test_health_check()
        self.test_rate_limiting_analysis()
        self.test_csrf_token()
        
        return self.generate_report()
    
    def run_auth_flow_tests(self) -> Dict[str, Any]:
        """Run authentication flow tests with smart rate limit handling"""
        self.logger.info("🔐 Running authentication flow tests...")
        
        # Basic setup
        self.test_health_check()
        
        # Try to get CSRF token (may be rate limited)
        csrf_success = self.test_csrf_token()
        if not csrf_success and self.config.rate_limit_mode != "skip":
            self.logger.warning("CSRF token rate limited, continuing without it for auth tests")
        
        # Authentication flow
        reg_success = self.test_user_registration()
        if reg_success:
            self.test_user_login()
            self.test_get_current_user()
        else:
            self.logger.warning("Registration failed/rate-limited, skipping dependent tests")
        
        return self.generate_report()
    
    def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive tests with intelligent rate limit management"""
        self.logger.info(f"🚀 Running comprehensive tests (mode: {self.config.rate_limit_mode})...")
        
        # Phase 1: Basic tests
        self.test_health_check()
        self.test_index()
        
        # Phase 2: Rate limiting analysis
        self.test_rate_limiting_analysis()
        
        # Phase 3: Authentication (with patience for rate limits)
        if self.config.rate_limit_mode != "skip":
            self.logger.info("⏳ Authentication phase - being patient with rate limits...")
            
            csrf_success = self.test_csrf_token()
            if csrf_success or self.config.rate_limit_mode == "aggressive":
                reg_success = self.test_user_registration()
                if reg_success:
                    login_success = self.test_user_login()
                    if login_success:
                        self.test_get_current_user()
                        
                        # Phase 4: Authenticated operations (if we have auth)
                        self.logger.info("📝 Testing authenticated operations...")
                        self.test_create_post()
                        self.test_file_upload()
                        
                        # Phase 5: Read operations (less rate-limited)
                        self.logger.info("📖 Testing read operations...")
                        self.test_get_posts()
                        self.test_search_posts()
                        
                        if self.test_posts:
                            self.test_get_single_post()
                            self.test_add_comment()
                            self.test_get_post_comments()
                        
                        if self.test_files:
                            self.test_get_file_info()
                            self.test_download_file()
        
        # Phase 6: Validation tests (always run)
        self.test_validation_errors()
        self.test_authentication_errors()
        
        # Phase 7: Cleanup
        self.test_cleanup_data()
        
        return self.generate_report()
    
    # ========================================
    # REMAINING TEST METHODS (ENHANCED)
    # ========================================
    
    def test_create_post(self) -> bool:
        """Test creating a blog post"""
        if not self.test_users or not self.test_users[0].token:
            self.add_result("Create Post", False, 0, None, "No authenticated user")
            return False
        
        post_data = {
            'title': f'Test Post {int(time.time())}',
            'content': f'This is a test post created at {datetime.now()}. It contains some sample content for testing purposes.',
            'status': 'published',
            'tags': 'test, api, blog'
        }
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', '/api/v1/posts',
                json=post_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                post_id = data.get('post_id')
                if post_id:
                    self.test_posts.append(post_id)
                self.add_result("Create Post", True, duration, 200, 
                              f"Post created: {post_data['title']}", data, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("Create Post", False, duration, 429, 
                              "Rate limited during post creation", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Create Post", False, duration, response.status_code, 
                              f"Post creation failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Create Post", False, 0, None, f"Exception: {e}")
            return False
    
    def test_get_posts(self) -> bool:
        """Test getting published posts"""
        try:
            response, duration, retries = self.make_request_with_retry('GET', '/api/v1/posts?limit=10&offset=0')
            
            if response.status_code == 200:
                data = response.json()
                posts = data.get('data', [])
                pagination = data.get('pagination', {})
                self.add_result("Get Posts", True, duration, 200, 
                              f"Retrieved {len(posts)} posts, total: {pagination.get('total', 0)}", 
                              {'count': len(posts), 'pagination': pagination}, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("Get Posts", False, duration, 429, 
                              "Rate limited during post retrieval", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Get Posts", False, duration, response.status_code, 
                              f"Failed to get posts: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Get Posts", False, 0, None, f"Exception: {e}")
            return False
    
    def test_get_single_post(self) -> bool:
        """Test getting a single post"""
        if not self.test_posts:
            self.add_result("Get Single Post", False, 0, None, "No test posts available")
            return False
        
        post_id = self.test_posts[0]
        
        try:
            response, duration, retries = self.make_request_with_retry('GET', f'/api/v1/posts/{post_id}')
            
            if response.status_code == 200:
                data = response.json()
                post_data = data.get('data', {})
                self.add_result("Get Single Post", True, duration, 200, 
                              f"Post retrieved: {post_data.get('title', 'Unknown')}", 
                              data, retry_count=retries)
                return True
            elif response.status_code == 404:
                self.add_result("Get Single Post", False, duration, 404, 
                              "Post not found", retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Get Single Post", False, duration, response.status_code, 
                              f"Failed to get post: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Get Single Post", False, 0, None, f"Exception: {e}")
            return False
    
    def test_search_posts(self) -> bool:
        """Test post search functionality"""
        search_query = "test"
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'GET', f'/api/v1/search/posts?q={search_query}&limit=10'
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('data', [])
                self.add_result("Search Posts", True, duration, 200, 
                              f"Search returned {len(results)} results for '{search_query}'", 
                              {'query': search_query, 'count': len(results)}, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("Search Posts", False, duration, 429, 
                              "Rate limited during search", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Search Posts", False, duration, response.status_code, 
                              f"Search failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Search Posts", False, 0, None, f"Exception: {e}")
            return False
    
    def test_add_comment(self) -> bool:
        """Test adding a comment to a post"""
        if not self.test_posts or not self.test_users or not self.test_users[0].token:
            self.add_result("Add Comment", False, 0, None, "No test posts or authenticated user")
            return False
        
        post_id = self.test_posts[0]
        comment_data = {
            'content': f'This is a test comment added at {datetime.now()}. Testing comment functionality.'
        }
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', f'/api/v1/posts/{post_id}/comments',
                json=comment_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                comment_id = data.get('comment_id')
                if comment_id:
                    self.test_comments.append(comment_id)
                self.add_result("Add Comment", True, duration, 200, 
                              "Comment added successfully", data, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("Add Comment", False, duration, 429, 
                              "Rate limited during comment creation", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Add Comment", False, duration, response.status_code, 
                              f"Comment creation failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Add Comment", False, 0, None, f"Exception: {e}")
            return False
    
    def test_get_post_comments(self) -> bool:
        """Test getting comments for a post"""
        if not self.test_posts:
            self.add_result("Get Post Comments", False, 0, None, "No test posts available")
            return False
        
        post_id = self.test_posts[0]
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'GET', f'/api/v1/posts/{post_id}/comments'
            )
            
            if response.status_code == 200:
                data = response.json()
                comments = data.get('data', [])
                self.add_result("Get Post Comments", True, duration, 200, 
                              f"Retrieved {len(comments)} comments", 
                              {'count': len(comments)}, retry_count=retries)
                return True
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Get Post Comments", False, duration, response.status_code, 
                              f"Failed to get comments: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Get Post Comments", False, 0, None, f"Exception: {e}")
            return False
    
    def test_file_upload(self) -> bool:
        """Test file upload functionality"""
        if not self.test_users or not self.test_users[0].token:
            self.add_result("File Upload", False, 0, None, "No authenticated user")
            return False
        
        if not os.path.exists(self.config.test_file_path):
            self.add_result("File Upload", False, 0, None, "Test file not found")
            return False
        
        try:
            with open(self.config.test_file_path, 'rb') as f:
                files = {'file': (self.config.test_file_path, f, 'text/plain')}
                
                response, duration, retries = self.make_request_with_retry(
                    'POST', '/api/v1/upload',
                    files=files
                )
            
            if response.status_code == 200:
                data = response.json()
                file_id = data.get('file_id')
                if file_id:
                    self.test_files.append(file_id)
                self.add_result("File Upload", True, duration, 200, 
                              f"File uploaded: {data.get('name', 'unknown')}, size: {data.get('size', 0)} bytes", 
                              data, retry_count=retries)
                return True
            elif response.status_code == 429:
                self.add_result("File Upload", False, duration, 429, 
                              "Rate limited during file upload", rate_limited=True, retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("File Upload", False, duration, response.status_code, 
                              f"File upload failed: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("File Upload", False, 0, None, f"Exception: {e}")
            return False
    
    def test_get_file_info(self) -> bool:
        """Test getting file information"""
        if not self.test_files:
            self.add_result("Get File Info", False, 0, None, "No test files available")
            return False
        
        file_id = self.test_files[0]
        
        try:
            response, duration, retries = self.make_request_with_retry('GET', f'/api/v1/files/{file_id}')
            
            if response.status_code == 200:
                data = response.json()
                file_info = data.get('data', {})
                self.add_result("Get File Info", True, duration, 200, 
                              f"File info retrieved: {file_info.get('name', 'unknown')}", 
                              data, retry_count=retries)
                return True
            elif response.status_code == 404:
                self.add_result("Get File Info", False, duration, 404, 
                              "File not found", retry_count=retries)
                return False
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                self.add_result("Get File Info", False, duration, response.status_code, 
                              f"Failed to get file info: {data.get('message', 'Unknown error')}", 
                              retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Get File Info", False, 0, None, f"Exception: {e}")
            return False
    
    def test_download_file(self) -> bool:
        """Test file download functionality"""
        if not self.test_files:
            self.add_result("Download File", False, 0, None, "No test files available")
            return False
        
        file_id = self.test_files[0]
        
        try:
            response, duration, retries = self.make_request_with_retry(
                'GET', f'/api/v1/files/{file_id}/download'
            )
            
            if response.status_code == 200:
                content_length = len(response.content)
                self.add_result("Download File", True, duration, 200, 
                              f"File downloaded successfully, size: {content_length} bytes", 
                              {'size': content_length}, retry_count=retries)
                return True
            elif response.status_code == 404:
                self.add_result("Download File", False, duration, 404, 
                              "File not found for download", retry_count=retries)
                return False
            else:
                self.add_result("Download File", False, duration, response.status_code, 
                              "File download failed", retry_count=retries)
                return False
                
        except Exception as e:
            self.add_result("Download File", False, 0, None, f"Exception: {e}")
            return False
    
    def test_validation_errors(self) -> bool:
        """Test API validation error handling"""
        tests_passed = 0
        total_tests = 0
        
        # Test invalid email registration
        total_tests += 1
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', '/api/v1/auth/register',
                json={'username': 'testuser', 'email': 'invalid-email', 'password': 'password'},
                headers={'Content-Type': 'application/json'},
                max_retries=0
            )
            if response.status_code == 400:
                tests_passed += 1
                self.logger.debug("✓ Invalid email validation working")
            else:
                self.logger.debug(f"✗ Invalid email validation failed: {response.status_code}")
        except Exception as e:
            self.logger.debug(f"✗ Invalid email test exception: {e}")
        
        # Test missing required fields
        total_tests += 1
        try:
            response, duration, retries = self.make_request_with_retry(
                'POST', '/api/v1/posts',
                json={'title': ''},  # Empty title should fail
                headers={'Content-Type': 'application/json'},
                max_retries=0
            )
            if response.status_code in [400, 401]:  # 400 for validation, 401 for auth
                tests_passed += 1
                self.logger.debug("✓ Empty title validation working")
            else:
                self.logger.debug(f"✗ Empty title validation failed: {response.status_code}")
        except Exception as e:
            self.logger.debug(f"✗ Empty title test exception: {e}")
        
        # Test invalid UUID
        total_tests += 1
        try:
            response, duration, retries = self.make_request_with_retry(
                'GET', '/api/v1/posts/invalid-uuid', max_retries=0
            )
            if response.status_code == 400:
                tests_passed += 1
                self.logger.debug("✓ Invalid UUID validation working")
            else:
                self.logger.debug(f"✗ Invalid UUID validation failed: {response.status_code}")
        except Exception as e:
            self.logger.debug(f"✗ Invalid UUID test exception: {e}")
        
        success = tests_passed == total_tests
        self.add_result("Validation Errors", success, 0, None, 
                      f"Validation tests: {tests_passed}/{total_tests} passed")
        return success
    
    def test_authentication_errors(self) -> bool:
        """Test authentication error handling"""
        # Test accessing protected endpoint without auth
        try:
            # Temporarily remove auth header
            auth_header = self.session.headers.get('Authorization')
            if auth_header:
                del self.session.headers['Authorization']
            
            response, duration, retries = self.make_request_with_retry(
                'GET', '/api/v1/auth/me', max_retries=0
            )
            
            # Restore auth header
            if auth_header:
                self.session.headers['Authorization'] = auth_header
            
            if response.status_code == 401:
                self.add_result("Authentication Errors", True, duration, 401, 
                              "Unauthorized access properly blocked")
                return True
            else:
                self.add_result("Authentication Errors", False, duration, response.status_code, 
                              "Unauthorized access not properly blocked")
                return False
                
        except Exception as e:
            self.add_result("Authentication Errors", False, 0, None, f"Exception: {e}")
            return False
    
    def test_cleanup_data(self) -> bool:
        """Clean up test data (delete created posts, files, etc.)"""
        cleanup_success = True
        
        # Delete test comments
        for comment_id in self.test_comments:
            try:
                response, duration, retries = self.make_request_with_retry(
                    'DELETE', f'/api/v1/comments/{comment_id}', max_retries=1
                )
                if response.status_code not in [200, 404]:
                    cleanup_success = False
                    self.logger.warning(f"Failed to delete comment {comment_id}: {response.status_code}")
            except Exception as e:
                cleanup_success = False
                self.logger.warning(f"Exception deleting comment {comment_id}: {e}")
        
        # Delete test posts
        for post_id in self.test_posts:
            try:
                response, duration, retries = self.make_request_with_retry(
                    'DELETE', f'/api/v1/posts/{post_id}', max_retries=1
                )
                if response.status_code not in [200, 404]:
                    cleanup_success = False
                    self.logger.warning(f"Failed to delete post {post_id}: {response.status_code}")
            except Exception as e:
                cleanup_success = False
                self.logger.warning(f"Exception deleting post {post_id}: {e}")
        
        # Delete test files
        for file_id in self.test_files:
            try:
                response, duration, retries = self.make_request_with_retry(
                    'DELETE', f'/api/v1/files/{file_id}', max_retries=1
                )
                if response.status_code not in [200, 404]:
                    cleanup_success = False
                    self.logger.warning(f"Failed to delete file {file_id}: {response.status_code}")
            except Exception as e:
                cleanup_success = False
                self.logger.warning(f"Exception deleting file {file_id}: {e}")
        
        # Logout user
        if self.test_users and self.test_users[0].token:
            try:
                response, duration, retries = self.make_request_with_retry(
                    'POST', '/api/v1/auth/logout', max_retries=1
                )
                if response.status_code == 200:
                    self.logger.info("User logged out successfully")
                else:
                    self.logger.warning(f"Logout failed: {response.status_code}")
            except Exception as e:
                self.logger.warning(f"Exception during logout: {e}")
        
        self.add_result("Cleanup Data", cleanup_success, 0, None, 
                      f"Cleanup {'completed' if cleanup_success else 'completed with warnings'}")
        return cleanup_success
    
    # ========================================
    # ENHANCED REPORTING
    # ========================================
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report with rate limit analysis"""
        total_duration = time.time() - self.start_time
        passed_tests = [r for r in self.results if r.success]
        failed_tests = [r for r in self.results if not r.success]
        rate_limited_tests = [r for r in self.results if r.rate_limited]
        
        report = {
            'summary': {
                'total_tests': len(self.results),
                'passed': len(passed_tests),
                'failed': len(failed_tests),
                'rate_limited': len(rate_limited_tests),
                'success_rate': (len(passed_tests) / len(self.results)) * 100 if self.results else 0,
                'total_duration': total_duration,
                'timestamp': datetime.now().isoformat(),
                'rate_limit_mode': self.config.rate_limit_mode
            },
            'rate_limit_stats': {
                'total_rate_limited_requests': self.rate_limit_stats['total_rate_limited'],
                'total_wait_time': self.rate_limit_stats['total_wait_time'],
                'max_wait_time': self.rate_limit_stats['max_wait_time'],
                'endpoints_rate_limited': list(self.rate_limit_stats['endpoints_rate_limited'])
            },
            'results': [
                {
                    'name': r.name,
                    'success': r.success,
                    'duration': r.duration,
                    'response_code': r.response_code,
                    'message': r.message,
                    'data': r.data,
                    'rate_limited': r.rate_limited,
                    'retry_count': r.retry_count
                }
                for r in self.results
            ],
            'failed_tests': [
                {
                    'name': r.name,
                    'message': r.message,
                    'response_code': r.response_code,
                    'rate_limited': r.rate_limited
                }
                for r in failed_tests
            ],
            'rate_limited_tests': [
                {
                    'name': r.name,
                    'message': r.message,
                    'response_code': r.response_code
                }
                for r in rate_limited_tests
            ]
        }
        
        # Print enhanced summary to console
        print("\n" + "="*80)
        print("🧪 ENHANCED API TEST RESULTS SUMMARY")
        print("="*80)
        print(f"Total Tests: {report['summary']['total_tests']}")
        print(f"Passed: {report['summary']['passed']} ✅")
        print(f"Failed: {report['summary']['failed']} ❌") 
        print(f"Rate Limited: {report['summary']['rate_limited']} 🚦")
        print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
        print(f"Total Duration: {report['summary']['total_duration']:.2f}s")
        print(f"Rate Limit Mode: {report['summary']['rate_limit_mode']}")
        
        # Rate limit statistics
        rl_stats = report['rate_limit_stats']
        if rl_stats['total_rate_limited_requests'] > 0:
            print(f"\n🚦 RATE LIMITING STATISTICS:")
            print(f"  Total Rate Limited Requests: {rl_stats['total_rate_limited_requests']}")
            print(f"  Total Wait Time: {rl_stats['total_wait_time']:.1f}s")
            print(f"  Max Single Wait: {rl_stats['max_wait_time']:.1f}s")
            print(f"  Affected Endpoints: {len(rl_stats['endpoints_rate_limited'])}")
            for endpoint in rl_stats['endpoints_rate_limited']:
                print(f"    • {endpoint}")
        
        if failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for test in failed_tests:
                rate_info = " [RATE LIMITED]" if test.rate_limited else ""
                print(f"  • {test.name}: {test.message}{rate_info}")
        
        if rate_limited_tests and not failed_tests:
            print(f"\n🚦 RATE LIMITED TESTS (not counted as failures):")
            for test in rate_limited_tests:
                print(f"  • {test.name}: {test.message}")
        
        print(f"\n💡 RECOMMENDATIONS:")
        if rl_stats['total_rate_limited_requests'] > 5:
            print("  • Consider using --rate-limit-mode patient for comprehensive testing")
            print("  • Or use --rate-limit-mode skip to test functionality only")
        elif len(failed_tests) > len(rate_limited_tests):
            print("  • Most failures are not rate-limit related")
            print("  • Check API server status and configuration")
        else:
            print("  • Rate limiting is working as expected")
            print("  • Use different test modes for different purposes")
        
        print("\n📊 Detailed results saved to 'api_test_results.log' and 'api_test_results.json'")
        print("="*80)
        
        # Save detailed report to JSON
        with open('api_test_results.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup_test_file()

# ========================================
# ENHANCED CLI INTERFACE
# ========================================

def main():
    parser = argparse.ArgumentParser(description='Enhanced API Test Client with Smart Rate Limit Handling')
    parser.add_argument('--url', default='http://localhost:8080', 
                       help='API base URL (default: http://localhost:8080)')
    parser.add_argument('--timeout', type=int, default=30, 
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Log level (default: INFO)')
    parser.add_argument('--mode', choices=['basic', 'auth', 'rate-limit', 'comprehensive'], 
                       default='comprehensive', help='Test mode (default: comprehensive)')
    parser.add_argument('--rate-limit-mode', choices=['smart', 'patient', 'aggressive', 'skip'], 
                       default='smart', help='Rate limit handling mode (default: smart)')
    parser.add_argument('--max-wait', type=int, default=120, 
                       help='Maximum seconds to wait for rate limit reset (default: 120)')
    parser.add_argument('--request-delay', type=float, default=0.5, 
                       help='Delay between requests in patient mode (default: 0.5)')
    parser.add_argument('--list-modes', action='store_true', 
                       help='List available test modes and rate limit modes')
    
    args = parser.parse_args()
    
    if args.list_modes:
        print("Test Modes:")
        print("  • basic: Health check, index, basic functionality")
        print("  • auth: Authentication flow tests")  
        print("  • rate-limit: Rate limiting analysis")
        print("  • comprehensive: Full test suite")
        print("\nRate Limit Modes:")
        print("  • smart: Intelligent delays, reasonable waits (recommended)")
        print("  • patient: Longer delays, waits for all rate limits")
        print("  • aggressive: Minimal delays, shorter waits")
        print("  • skip: Skip rate-limited requests, test functionality only")
        return
    
    # Create enhanced test configuration
    config = TestConfig(
        base_url=args.url,
        timeout=args.timeout,
        log_level=args.log_level,
        rate_limit_mode=args.rate_limit_mode,
        max_wait_time=args.max_wait,
        request_delay=args.request_delay
    )
    
    # Create enhanced test client
    client = EnhancedAPITestClient(config)
    
    try:
        # Run tests based on mode
        if args.mode == 'basic':
            report = client.run_basic_tests()
        elif args.mode == 'auth':
            report = client.run_auth_flow_tests()
        elif args.mode == 'rate-limit':
            report = client.run_rate_limit_tests()
        else:  # comprehensive
            report = client.run_comprehensive_tests()
        
        # Exit with appropriate code (ignore rate-limited tests for exit code)
        non_rate_limit_failures = len([r for r in client.results if not r.success and not r.rate_limited])
        exit_code = 0 if non_rate_limit_failures == 0 else 1
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        client.logger.info("Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Test execution failed: {e}")
        client.logger.error(f"Test execution failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
