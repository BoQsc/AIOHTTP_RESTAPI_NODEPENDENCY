#!/usr/bin/env python3
"""
Corrected Rate Limiting Test Script
Fixed to connect to HTTP localhost:8080 instead of HTTPS
"""

import requests
import time
import json
from typing import Dict, Any

def test_rate_limiting():
    """Test rate limiting with correct URL"""
    base_url = "http://localhost:8080"  # FIXED: Use HTTP, not HTTPS
    
    print("🧪 Testing Rate Limiting Server")
    print("=" * 50)
    print(f"Server URL: {base_url}")
    print()
    
    # Test 1: Server Health Check
    print("🏥 Testing Server Health...")
    try:
        response = requests.get(f"{base_url}/api/v1/health", timeout=5)
        if response.status_code == 200:
            print("✅ Server is healthy")
            health_data = response.json()
            print(f"   Environment: {health_data.get('environment')}")
            if 'rate_limiter' in health_data:
                rl_stats = health_data['rate_limiter']
                print(f"   Rate Limiter - Total: {rl_stats.get('total_requests', 0)}, Blocked: {rl_stats.get('blocked_requests', 0)}")
        else:
            print(f"❌ Server returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Make sure the server is running on http://localhost:8080")
        return False
    
    print()
    
    # Test 2: CSRF Token Rate Limiting (3 per minute)
    print("🔒 Testing CSRF Token Rate Limiting...")
    print("   Limit: 3 requests per minute")
    print("   Making 5 requests to trigger rate limiting...")
    
    success_count = 0
    blocked_count = 0
    
    for i in range(5):
        try:
            response = requests.get(f"{base_url}/api/v1/csrf-token", timeout=5)
            status_code = response.status_code
            
            print(f"   Request {i+1}: HTTP {status_code}", end="")
            
            if status_code == 200:
                success_count += 1
                print(" ✅ ALLOWED")
                # Show rate limit headers if present
                headers = response.headers
                remaining = headers.get('X-RateLimit-IP-Remaining')
                if remaining:
                    print(f"      Remaining: {remaining}")
            elif status_code == 429:
                blocked_count += 1
                print(" 🚫 RATE LIMITED")
                try:
                    error_data = response.json()
                    retry_after = error_data.get('rate_limit', {}).get('retry_after_seconds')
                    if retry_after:
                        print(f"      Retry after: {retry_after} seconds")
                except:
                    pass
            else:
                print(f" ❓ Unexpected status")
            
            time.sleep(0.3)  # Small delay between requests
            
        except Exception as e:
            print(f"   Request {i+1}: ❌ Error - {e}")
    
    print(f"\n   Results: {success_count} allowed, {blocked_count} blocked")
    
    if success_count == 3 and blocked_count >= 1:
        print("   ✅ CSRF rate limiting working correctly!")
    else:
        print("   ⚠️  Unexpected results - check rate limiting configuration")
    
    print()
    
    # Test 3: Login Rate Limiting (5 per 5 minutes)
    print("🔑 Testing Login Rate Limiting...")
    print("   Limit: 5 requests per 5 minutes")
    print("   Making 7 login attempts...")
    
    login_data = {
        "email": "test@example.com",
        "password": "password"
    }
    
    login_success = 0
    login_blocked = 0
    
    for i in range(7):
        try:
            response = requests.post(
                f"{base_url}/api/v1/auth/login",
                json=login_data,
                timeout=5
            )
            
            status_code = response.status_code
            print(f"   Login {i+1}: HTTP {status_code}", end="")
            
            if status_code == 200:
                login_success += 1
                print(" ✅ ALLOWED")
            elif status_code == 401:
                login_success += 1  # Still counted as allowed request (just invalid creds)
                print(" 🔐 Invalid credentials (but not rate limited)")
            elif status_code == 429:
                login_blocked += 1
                print(" 🚫 RATE LIMITED")
            else:
                print(f" ❓ Status {status_code}")
            
            time.sleep(0.2)
            
        except Exception as e:
            print(f"   Login {i+1}: ❌ Error - {e}")
    
    print(f"\n   Results: {login_success} allowed, {login_blocked} blocked")
    
    if login_success == 5 and login_blocked >= 1:
        print("   ✅ Login rate limiting working correctly!")
    else:
        print("   ⚠️  Check login rate limiting - may need different test credentials")
    
    print()
    
    # Test 4: Search Rate Limiting (10 per minute)
    print("🔍 Testing Search Rate Limiting...")
    print("   Limit: 10 requests per minute")
    print("   Making 12 search requests...")
    
    search_success = 0
    search_blocked = 0
    
    for i in range(12):
        try:
            response = requests.get(f"{base_url}/api/v1/search/posts?q=test{i}", timeout=5)
            status_code = response.status_code
            
            if status_code == 200:
                search_success += 1
            elif status_code == 429:
                search_blocked += 1
            
            if i < 3 or i >= 9:  # Only show first few and last few
                print(f"   Search {i+1}: HTTP {status_code}")
            elif i == 3:
                print("   ... (continuing) ...")
            
            time.sleep(0.1)
            
        except Exception as e:
            print(f"   Search {i+1}: ❌ Error - {e}")
    
    print(f"\n   Results: {search_success} allowed, {search_blocked} blocked")
    
    if search_success == 10 and search_blocked >= 1:
        print("   ✅ Search rate limiting working correctly!")
    else:
        print("   ⚠️  Search rate limiting may need adjustment")
    
    print()
    
    # Test 5: Get Rate Limit Statistics
    print("📊 Getting Rate Limit Statistics...")
    try:
        response = requests.get(f"{base_url}/api/v1/admin/rate-limit-stats", timeout=5)
        if response.status_code == 200:
            stats = response.json().get('data', {})
            print("   ✅ Statistics retrieved:")
            print(f"      Total requests: {stats.get('total_requests', 0)}")
            print(f"      Allowed requests: {stats.get('allowed_requests', 0)}")
            print(f"      Blocked requests: {stats.get('blocked_requests', 0)}")
            print(f"      Active keys: {stats.get('active_keys', 0)}")
            print(f"      Environment: {stats.get('environment', 'unknown')}")
            
            block_rate = stats.get('block_rate', 0)
            print(f"      Block rate: {block_rate:.1%}")
        else:
            print(f"   ⚠️  Could not get stats (HTTP {response.status_code})")
    except Exception as e:
        print(f"   ❌ Error getting stats: {e}")
    
    print()
    
    # Summary
    print("🏁 Rate Limiting Test Summary")
    print("=" * 40)
    
    total_tests = 3
    passed_tests = 0
    
    if success_count == 3 and blocked_count >= 1:
        passed_tests += 1
        print("✅ CSRF rate limiting: PASSED")
    else:
        print("❌ CSRF rate limiting: FAILED")
    
    if login_success == 5 and login_blocked >= 1:
        passed_tests += 1
        print("✅ Login rate limiting: PASSED")
    else:
        print("❌ Login rate limiting: FAILED")
    
    if search_success == 10 and search_blocked >= 1:
        passed_tests += 1
        print("✅ Search rate limiting: PASSED")
    else:
        print("❌ Search rate limiting: FAILED")
    
    print(f"\nResults: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All rate limiting tests PASSED!")
        return True
    else:
        print("⚠️  Some tests failed - check configuration")
        return False

def quick_test():
    """Quick test to verify rate limiting is working"""
    base_url = "http://localhost:8080"
    
    print("⚡ Quick Rate Limiting Test")
    print("Making 4 rapid requests to CSRF endpoint...")
    print("Expected: First 3 should succeed, 4th should be rate limited")
    print()
    
    for i in range(4):
        try:
            response = requests.get(f"{base_url}/api/v1/csrf-token", timeout=5)
            status = response.status_code
            
            if status == 200:
                print(f"Request {i+1}: ✅ SUCCESS (HTTP 200)")
            elif status == 429:
                print(f"Request {i+1}: 🚫 RATE LIMITED (HTTP 429)")
            else:
                print(f"Request {i+1}: ❓ HTTP {status}")
            
        except Exception as e:
            print(f"Request {i+1}: ❌ ERROR - {e}")
        
        time.sleep(0.2)

if __name__ == "__main__":
    import sys
    
    print("🧪 Rate Limiting Test Suite")
    print("Connecting to: http://localhost:8080")
    print()
    
    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        quick_test()
    else:
        print("Choose test mode:")
        print("1. Full comprehensive test")
        print("2. Quick test (4 requests)")
        print()
        
        choice = input("Enter choice (1 or 2), or press Enter for quick test: ").strip()
        
        if choice == "1":
            test_rate_limiting()
        else:
            quick_test()
