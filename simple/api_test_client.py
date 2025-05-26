#!/usr/bin/env python3
"""
Comprehensive test client for the enhanced API server
Tests all endpoints, authentication, validation, file uploads, and error handling
"""

import requests
import json
import uuid
import time
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APITestClient:
    """Comprehensive test client for the API server"""
    
    def __init__(self, base_url: str = "https://localhost"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # For self-signed SSL certs
        self.csrf_token: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.current_user: Optional[Dict] = None
        self.test_results: List[Dict] = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": time.time()
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name} - {details}")
        
    def get_csrf_token(self) -> bool:
        """Get CSRF token"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/csrf-token")
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get('csrf_token')
                self.log_test("Get CSRF Token", True, f"Token: {self.csrf_token[:10]}...")
                return True
            else:
                self.log_test("Get CSRF Token", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Get CSRF Token", False, f"Error: {str(e)}")
            return False
    
    def register_user(self, username: str, email: str, password: str) -> bool:
        """Register a new user"""
        try:
            headers = {
                "X-CSRF-Token": self.csrf_token,
                "Content-Type": "application/json"
            } if self.csrf_token else {"Content-Type": "application/json"}
            data = {
                "username": username,
                "email": email,
                "password": password
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/register",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.log_test("User Registration", True, f"User ID: {result.get('user_id')}")
                return True
            else:
                self.log_test("User Registration", False, f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("User Registration", False, f"Error: {str(e)}")
            return False
    
    def login_user(self, email: str, password: str) -> bool:
        """Login user"""
        try:
            headers = {
                "X-CSRF-Token": self.csrf_token,
                "Content-Type": "application/json"
            } if self.csrf_token else {"Content-Type": "application/json"}
            data = {
                "email": email,
                "password": password
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.auth_token = result.get('token')
                self.current_user = result.get('user')
                self.log_test("User Login", True, f"Token: {self.auth_token[:10]}...")
                return True
            else:
                self.log_test("User Login", False, f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("User Login", False, f"Error: {str(e)}")
            return False
    
    def get_current_user(self) -> bool:
        """Get current user info"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}"
            }
            
            response = self.session.get(
                f"{self.base_url}/api/v1/auth/me",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                user = result.get('user')
                self.log_test("Get Current User", True, f"Username: {user.get('username')}")
                return True
            else:
                self.log_test("Get Current User", False, f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Get Current User", False, f"Error: {str(e)}")
            return False
    
    def create_post(self, title: str, content: str, status: str = "published") -> Optional[str]:
        """Create a blog post"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token,
                "Content-Type": "application/json"
            }
            data = {
                "title": title,
                "content": content,
                "status": status,
                "tags": "test,api"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/posts",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                post_id = result.get('post_id')
                self.log_test("Create Post", True, f"Post ID: {post_id}")
                return post_id
            else:
                self.log_test("Create Post", False, f"Status: {response.status_code}, Response: {response.text}")
                return None
                
        except Exception as e:
            self.log_test("Create Post", False, f"Error: {str(e)}")
            return None
    
    def get_post(self, post_id: str) -> bool:
        """Get a specific post"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/posts/{post_id}")
            
            if response.status_code == 200:
                result = response.json()
                post = result.get('data')
                self.log_test("Get Post", True, f"Title: {post.get('title')}")
                return True
            else:
                self.log_test("Get Post", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Post", False, f"Error: {str(e)}")
            return False
    
    def get_published_posts(self, limit: int = 10, offset: int = 0) -> bool:
        """Get published posts with pagination"""
        try:
            params = {"limit": limit, "offset": offset}
            response = self.session.get(
                f"{self.base_url}/api/v1/posts",
                params=params
            )
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', [])
                pagination = result.get('pagination', {})
                self.log_test("Get Published Posts", True, f"Found {len(data)} posts, Total: {pagination.get('total')}")
                return True
            else:
                self.log_test("Get Published Posts", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Published Posts", False, f"Error: {str(e)}")
            return False
    
    def update_post(self, post_id: str, title: str = None, content: str = None) -> bool:
        """Update a post"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token
            }
            data = {}
            if title:
                data["title"] = title
            if content:
                data["content"] = content
            
            response = self.session.put(
                f"{self.base_url}/api/v1/posts/{post_id}",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                self.log_test("Update Post", True, f"Updated post {post_id}")
                return True
            else:
                self.log_test("Update Post", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Update Post", False, f"Error: {str(e)}")
            return False
    
    def search_posts(self, query: str) -> bool:
        """Search posts"""
        try:
            params = {"q": query, "limit": 10}
            response = self.session.get(
                f"{self.base_url}/api/v1/search/posts",
                params=params
            )
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', [])
                self.log_test("Search Posts", True, f"Found {len(data)} posts for '{query}'")
                return True
            else:
                self.log_test("Search Posts", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Search Posts", False, f"Error: {str(e)}")
            return False
    
    def create_comment(self, post_id: str, content: str) -> Optional[str]:
        """Add comment to a post"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token
            }
            data = {"content": content}
            
            response = self.session.post(
                f"{self.base_url}/api/v1/posts/{post_id}/comments",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                comment_id = result.get('comment_id')
                self.log_test("Create Comment", True, f"Comment ID: {comment_id}")
                return comment_id
            else:
                self.log_test("Create Comment", False, f"Status: {response.status_code}")
                return None
                
        except Exception as e:
            self.log_test("Create Comment", False, f"Error: {str(e)}")
            return None
    
    def get_post_comments(self, post_id: str) -> bool:
        """Get comments for a post"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/posts/{post_id}/comments")
            
            if response.status_code == 200:
                result = response.json()
                comments = result.get('data', [])
                self.log_test("Get Post Comments", True, f"Found {len(comments)} comments")
                return True
            else:
                self.log_test("Get Post Comments", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Post Comments", False, f"Error: {str(e)}")
            return False
    
    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload a file"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'text/plain')}
                response = self.session.post(
                    f"{self.base_url}/api/v1/upload",
                    files=files,
                    headers=headers
                )
            
            if response.status_code == 200:
                result = response.json()
                file_id = result.get('file_id')
                self.log_test("Upload File", True, f"File ID: {file_id}, Size: {result.get('size')} bytes")
                return file_id
            else:
                self.log_test("Upload File", False, f"Status: {response.status_code}, Response: {response.text}")
                return None
                
        except Exception as e:
            self.log_test("Upload File", False, f"Error: {str(e)}")
            return None
    
    def get_file_info(self, file_id: str) -> bool:
        """Get file metadata"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/files/{file_id}")
            
            if response.status_code == 200:
                result = response.json()
                file_info = result.get('data')
                self.log_test("Get File Info", True, f"Name: {file_info.get('name')}")
                return True
            else:
                self.log_test("Get File Info", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get File Info", False, f"Error: {str(e)}")
            return False
    
    def download_file(self, file_id: str) -> bool:
        """Download a file"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/files/{file_id}/download")
            
            if response.status_code == 200:
                content_length = len(response.content)
                self.log_test("Download File", True, f"Downloaded {content_length} bytes")
                return True
            else:
                self.log_test("Download File", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Download File", False, f"Error: {str(e)}")
            return False
    
    def delete_post(self, post_id: str) -> bool:
        """Delete a post"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token
            }
            
            response = self.session.delete(
                f"{self.base_url}/api/v1/posts/{post_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                self.log_test("Delete Post", True, f"Deleted post {post_id}")
                return True
            else:
                self.log_test("Delete Post", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Delete Post", False, f"Error: {str(e)}")
            return False
    
    def logout_user(self) -> bool:
        """Logout user"""
        try:
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "X-CSRF-Token": self.csrf_token,
                "Content-Type": "application/json"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/logout",
                headers=headers
            )
            
            if response.status_code == 200:
                self.log_test("User Logout", True, "Successfully logged out")
                self.auth_token = None
                self.current_user = None
                return True
            else:
                self.log_test("User Logout", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("User Logout", False, f"Error: {str(e)}")
            return False
    
    def test_validation_errors(self) -> None:
        """Test various validation scenarios"""
        # Test invalid email registration
        try:
            headers = {
                "X-CSRF-Token": self.csrf_token,
                "Content-Type": "application/json"
            } if self.csrf_token else {"Content-Type": "application/json"}
            data = {
                "username": "testuser",
                "email": "invalid-email",
                "password": "test123"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/register",
                json=data,
                headers=headers
            )
            
            if response.status_code == 400:
                self.log_test("Validation - Invalid Email", True, "Correctly rejected invalid email")
            else:
                self.log_test("Validation - Invalid Email", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Validation - Invalid Email", False, f"Error: {str(e)}")
        
        # Test short password
        try:
            data = {
                "username": "testuser2",
                "email": "test2@example.com",
                "password": "123"  # Too short
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/register",
                json=data,
                headers=headers
            )
            
            if response.status_code == 400:
                self.log_test("Validation - Short Password", True, "Correctly rejected short password")
            else:
                self.log_test("Validation - Short Password", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Validation - Short Password", False, f"Error: {str(e)}")
    
    def test_unauthorized_access(self) -> None:
        """Test unauthorized access scenarios"""
        # Try to create post without auth
        try:
            data = {
                "title": "Test Post",
                "content": "This should fail"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/posts",
                json=data
            )
            
            if response.status_code == 401:
                self.log_test("Unauthorized - Create Post", True, "Correctly rejected unauthorized request")
            else:
                self.log_test("Unauthorized - Create Post", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Unauthorized - Create Post", False, f"Error: {str(e)}")
    
    def create_temp_file(self) -> str:
        """Create a temporary test file"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_file.write("This is a test file for API upload testing.\nLine 2\nLine 3")
        temp_file.flush()
        temp_file.close()
        return temp_file.name
    
    def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run all tests in sequence"""
        print("🚀 Starting comprehensive API tests...\n")
        
        # Generate unique test data
        test_id = str(uuid.uuid4())[:8]
        test_username = f"testuser_{test_id}"
        test_email = f"test_{test_id}@example.com"
        test_password = "testpass123"
        
        # 1. Get CSRF Token
        if not self.get_csrf_token():
            print("❌ Cannot continue without CSRF token")
            return self.get_summary()
        
        # 2. Test validation errors
        print("\n🔍 Testing validation...")
        self.test_validation_errors()
        
        # 3. Test unauthorized access
        print("\n🔒 Testing unauthorized access...")
        self.test_unauthorized_access()
        
        # 4. Register user
        print(f"\n👤 Testing user registration...")
        if not self.register_user(test_username, test_email, test_password):
            print("❌ Cannot continue without user registration")
            return self.get_summary()
        
        # 5. Login user
        print(f"\n🔑 Testing user login...")
        if not self.login_user(test_email, test_password):
            print("❌ Cannot continue without login")
            return self.get_summary()
        
        # 6. Get current user
        print(f"\n📋 Testing get current user...")
        self.get_current_user()
        
        # 7. Create posts
        print(f"\n📝 Testing post creation...")
        post_id1 = self.create_post("Test Post 1", "This is the content of test post 1")
        post_id2 = self.create_post("Python Tutorial", "Learn Python programming with this comprehensive guide")
        
        if post_id1:
            # 8. Get specific post
            print(f"\n📖 Testing get post...")
            self.get_post(post_id1)
            
            # 9. Update post
            print(f"\n✏️ Testing post update...")
            self.update_post(post_id1, title="Updated Test Post 1")
        
        # 10. Get published posts
        print(f"\n📚 Testing get published posts...")
        self.get_published_posts(limit=5, offset=0)
        
        # 11. Search posts
        print(f"\n🔍 Testing post search...")
        self.search_posts("Python")
        
        if post_id1:
            # 12. Create comments
            print(f"\n💬 Testing comment creation...")
            comment_id = self.create_comment(post_id1, "This is a test comment")
            
            # 13. Get post comments
            print(f"\n💬 Testing get comments...")
            self.get_post_comments(post_id1)
        
        # 14. File upload tests
        print(f"\n📁 Testing file operations...")
        temp_file = self.create_temp_file()
        try:
            file_id = self.upload_file(temp_file)
            if file_id:
                self.get_file_info(file_id)
                self.download_file(file_id)
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file)
            except:
                pass
        
        # 15. Cleanup - delete posts
        print(f"\n🗑️ Testing post deletion...")
        if post_id1:
            self.delete_post(post_id1)
        if post_id2:
            self.delete_post(post_id2)
        
        # 16. Logout
        print(f"\n👋 Testing logout...")
        self.logout_user()
        
        return self.get_summary()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        summary = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "results": self.test_results
        }
        
        print(f"\n📊 TEST SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"   - {result['test']}: {result['details']}")
        
        return summary

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='API Test Client')
    parser.add_argument('--url', default='https://localhost', help='Base URL of the API server')
    parser.add_argument('--save-results', action='store_true', help='Save test results to JSON file')
    
    args = parser.parse_args()
    
    # Create test client
    client = APITestClient(args.url)
    
    # Run comprehensive tests
    try:
        summary = client.run_comprehensive_tests()
        
        # Save results if requested
        if args.save_results:
            filename = f"api_test_results_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            print(f"\n💾 Results saved to {filename}")
        
        # Exit with appropriate code
        exit_code = 0 if summary['success_rate'] == 100 else 1
        exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️ Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n💥 Test runner error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
