#!/usr/bin/env python3
"""
Rate Limiting Test Script
Tests rate limiting functionality and demonstrates different scenarios
"""

import requests
import time
import threading
import concurrent.futures
from typing import List, Dict, Any
import urllib3
import json

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RateLimitTester:
    """Test rate limiting functionality"""
    
    def __init__(self, base_url: str = "https://localhost"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.results = []
    
    def log_result(self, test_name: str, success: bool, details: str = "", response_data: Dict = None):
        """Log test result"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": time.time(),
            "response_data": response_data
        }
        self.results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if details:
            print(f"    {details}")
        if response_data and 'rate_limit' in response_data:
            rl = response_data['rate_limit']
            print(f"    Rate Limit: {rl.get('remaining', 'N/A')}/{rl.get('limit', 'N/A')} remaining")
    
    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            url = f"{self.base_url}{endpoint}"
            response = getattr(self.session, method.lower())(url, **kwargs)
            return response
        except Exception as e:
            print(f"Request error: {e}")
            return None
    
    def test_basic_rate_limiting(self):
        """Test basic rate limiting on CSRF token endpoint"""
        print("\n🔒 Testing Basic Rate Limiting...")
        
        endpoint = "/api/v1/csrf-token"
        success_count = 0
        rate_limited_count = 0
        
        # Make rapid requests to trigger rate limiting
        for i in range(15):  # Try more than typical limit
            response = self.make_request("GET", endpoint)
            
            if response and response.status_code == 200:
                success_count += 1
                headers = dict(response.headers)
                remaining_ip = headers.get('X-RateLimit-Remaining-IP', 'N/A')
                print(f"  Request {i+1}: ✅ Success (IP remaining: {remaining_ip})")
                
            elif response and response.status_code == 429:
                rate_limited_count += 1
                try:
                    data = response.json()
                    retry_after = data.get('rate_limit', {}).get('retry_after_seconds', 'N/A')
                    print(f"  Request {i+1}: 🚫 Rate Limited (retry after: {retry_after}s)")
                except:
                    print(f"  Request {i+1}: 🚫 Rate Limited")
                
                # Stop after first rate limit to avoid spam
                break
            else:
                print(f"  Request {i+1}: ❌ Error {response.status_code if response else 'No response'}")
            
            time.sleep(0.1)  # Small delay between requests
        
        if rate_limited_count > 0:
            self.log_result(
                "Basic Rate Limiting", 
                True, 
                f"Successfully triggered rate limiting after {success_count} requests"
            )
        else:
            self.log_result(
                "Basic Rate Limiting", 
                False, 
                f"Rate limiting not triggered after {success_count} requests"
            )
    
    def test_login_rate_limiting(self):
        """Test rate limiting on login endpoint (typically more restrictive)"""
        print("\n🔑 Testing Login Rate Limiting...")
        
        # Get CSRF token first
        csrf_response = self.make_request("GET", "/api/v1/csrf-token")
        csrf_token = None
        if csrf_response and csrf_response.status_code == 200:
            csrf_token = csrf_response.json().get('csrf_token')
        
        if not csrf_token:
            self.log_result("Login Rate Limiting", False, "Could not get CSRF token")
            return
        
        endpoint = "/api/v1/auth/login"
        headers = {
            "X-CSRF-Token": csrf_token,
            "Content-Type": "application/json"
        }
        
        # Invalid login data to trigger rate limiting
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        success_count = 0
        rate_limited_count = 0
        
        # Make multiple login attempts
        for i in range(10):
            response = self.make_request("POST", endpoint, json=login_data, headers=headers)
            
            if response and response.status_code in [400, 401]:  # Invalid credentials
                success_count += 1
                print(f"  Login attempt {i+1}: ✅ Processed (invalid credentials)")
                
            elif response and response.status_code == 429:
                rate_limited_count += 1
                try:
                    data = response.json()
                    retry_after = data.get('rate_limit', {}).get('retry_after_seconds', 'N/A')
                    print(f"  Login attempt {i+1}: 🚫 Rate Limited (retry after: {retry_after}s)")
                except:
                    print(f"  Login attempt {i+1}: 🚫 Rate Limited")
                break
            else:
                print(f"  Login attempt {i+1}: ❌ Unexpected status {response.status_code if response else 'No response'}")
            
            time.sleep(0.5)  # Delay between login attempts
        
        if rate_limited_count > 0:
            self.log_result(
                "Login Rate Limiting", 
                True, 
                f"Login rate limiting triggered after {success_count} attempts"
            )
        else:
            self.log_result(
                "Login Rate Limiting", 
                False, 
                f"Login rate limiting not triggered after {success_count} attempts"
            )
    
    def test_concurrent_requests(self):
        """Test rate limiting with concurrent requests"""
        print("\n⚡ Testing Concurrent Request Rate Limiting...")
        
        def make_concurrent_request(request_id: int) -> Dict[str, Any]:
            """Make a single request and return result"""
            start_time = time.time()
            response = self.make_request("GET", "/api/v1/csrf-token")
            end_time = time.time()
            
            result = {
                "request_id": request_id,
                "status_code": response.status_code if response else None,
                "duration": end_time - start_time,
                "timestamp": start_time
            }
            
            if response and response.status_code == 429:
                try:
                    result["rate_limit_data"] = response.json()
                except:
                    pass
            
            return result
        
        # Make 20 concurrent requests
        num_requests = 20
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(make_concurrent_request, i) 
                for i in range(num_requests)
            ]
            
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Analyze results
        successful = [r for r in results if r['status_code'] == 200]
        rate_limited = [r for r in results if r['status_code'] == 429]
        errors = [r for r in results if r['status_code'] not in [200, 429]]
        
        print(f"  Concurrent requests: {num_requests}")
        print(f"  Successful: {len(successful)}")
        print(f"  Rate limited: {len(rate_limited)}")
        print(f"  Errors: {len(errors)}")
        
        # Rate limiting should protect against concurrent abuse
        if len(rate_limited) > 0:
            self.log_result(
                "Concurrent Rate Limiting", 
                True, 
                f"Rate limiting protected against {len(rate_limited)}/{num_requests} concurrent requests"
            )
        else:
            self.log_result(
                "Concurrent Rate Limiting", 
                False, 
                "No rate limiting triggered with concurrent requests"
            )
    
    def test_rate_limit_headers(self):
        """Test rate limit headers in responses"""
        print("\n📊 Testing Rate Limit Headers...")
        
        response = self.make_request("GET", "/api/v1/csrf-token")
        
        if response and response.status_code == 200:
            headers = dict(response.headers)
            
            # Check for rate limit headers
            expected_headers = [
                'X-RateLimit-Remaining-IP',
                'X-RateLimit-Reset-IP'
            ]
            
            found_headers = []
            for header in expected_headers:
                if header in headers:
                    found_headers.append(f"{header}: {headers[header]}")
            
            if found_headers:
                self.log_result(
                    "Rate Limit Headers", 
                    True, 
                    f"Found headers: {', '.join(found_headers)}"
                )
            else:
                self.log_result(
                    "Rate Limit Headers", 
                    False, 
                    "No rate limit headers found in response"
                )
        else:
            self.log_result(
                "Rate Limit Headers", 
                False, 
                f"Could not get response for header test: {response.status_code if response else 'No response'}"
            )
    
    def test_rate_limit_reset(self):
        """Test rate limit reset functionality"""
        print("\n⏰ Testing Rate Limit Reset...")
        
        # First, trigger rate limiting
        endpoint = "/api/v1/csrf-token"
        
        # Make requests until rate limited
        for i in range(20):
            response = self.make_request("GET", endpoint)
            if response and response.status_code == 429:
                try:
                    data = response.json()
                    retry_after = data.get('rate_limit', {}).get('retry_after_seconds')
                    
                    if retry_after and retry_after > 0:
                        print(f"  Rate limited! Waiting {retry_after} seconds for reset...")
                        
                        # Wait for rate limit to reset
                        time.sleep(min(retry_after + 1, 10))  # Cap wait time for testing
                        
                        # Try request again
                        response2 = self.make_request("GET", endpoint)
                        if response2 and response2.status_code == 200:
                            self.log_result(
                                "Rate Limit Reset", 
                                True, 
                                f"Rate limit reset after {retry_after} seconds"
                            )
                        else:
                            self.log_result(
                                "Rate Limit Reset", 
                                False, 
                                f"Rate limit not reset after waiting"
                            )
                        return
                except:
                    pass
            time.sleep(0.1)
        
        self.log_result(
            "Rate Limit Reset", 
            False, 
            "Could not trigger rate limiting to test reset"
        )
    
    def test_admin_rate_limit_stats(self):
        """Test rate limit statistics endpoint"""
        print("\n📈 Testing Rate Limit Statistics...")
        
        response = self.make_request("GET", "/api/v1/admin/rate-limit-stats")
        
        if response:
            if response.status_code == 403:
                self.log_result(
                    "Rate Limit Stats Access Control", 
                    True, 
                    "Correctly blocked non-admin access to stats"
                )
            elif response.status_code == 401:
                self.log_result(
                    "Rate Limit Stats Authentication", 
                    True, 
                    "Correctly requires authentication for stats"
                )
            elif response.status_code == 200:
                try:
                    data = response.json()
                    stats = data.get('data', {})
                    self.log_result(
                        "Rate Limit Stats", 
                        True, 
                        f"Got stats: {stats.get('total_requests', 0)} total requests"
                    )
                except:
                    self.log_result(
                        "Rate Limit Stats", 
                        False, 
                        "Invalid JSON in stats response"
                    )
            else:
                self.log_result(
                    "Rate Limit Stats", 
                    False, 
                    f"Unexpected status code: {response.status_code}"
                )
        else:
            self.log_result(
                "Rate Limit Stats", 
                False, 
                "No response from stats endpoint"
            )
    
    def run_all_tests(self):
        """Run all rate limiting tests"""
        print("🚀 Starting Rate Limiting Tests...")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run individual tests
        self.test_basic_rate_limiting()
        self.test_login_rate_limiting()
        self.test_concurrent_requests()
        self.test_rate_limit_headers()
        self.test_rate_limit_reset()
        self.test_admin_rate_limit_stats()
        
        # Summary
        total_time = time.time() - start_time
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("📊 RATE LIMITING TEST SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Success Rate: {(passed_tests/total_tests*100):.1f}%")
        print(f"   Total Time: {total_time:.2f}s")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.results:
                if not result['success']:
                    print(f"   - {result['test']}: {result['details']}")
        
        return {
            'total_tests': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'success_rate': (passed_tests/total_tests*100) if total_tests > 0 else 0,
            'results': self.results
        }

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rate Limiting Test Client')
    parser.add_argument('--url', default='https://localhost', help='Base URL of the API server')
    parser.add_argument('--save-results', action='store_true', help='Save test results to JSON file')
    
    args = parser.parse_args()
    
    # Create and run tests
    tester = RateLimitTester(args.url)
    
    try:
        summary = tester.run_all_tests()
        
        # Save results if requested
        if args.save_results:
            filename = f"rate_limit_test_results_{int(time.time())}.json"
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
