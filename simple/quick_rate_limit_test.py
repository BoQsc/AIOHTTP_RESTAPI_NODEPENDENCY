#!/usr/bin/env python3
"""
Quick Rate Limit Test - Debug Version
Tests rate limiting with detailed response analysis
"""

import requests
import time
import json

def test_csrf_rate_limiting():
    """Test CSRF rate limiting with detailed debugging"""
    base_url = "http://localhost:8080"
    
    print("🔍 Debugging Rate Limiting")
    print("=" * 50)
    
    for i in range(6):
        print(f"\n📡 Request {i+1}:")
        
        try:
            response = requests.get(f"{base_url}/api/v1/csrf-token", timeout=5)
            
            print(f"   Status Code: {response.status_code}")
            print(f"   Content Length: {len(response.content)} bytes")
            
            # Check headers
            rate_headers = {k: v for k, v in response.headers.items() 
                          if 'ratelimit' in k.lower() or 'retry-after' in k.lower()}
            if rate_headers:
                print(f"   Rate Headers: {rate_headers}")
            
            # Parse response
            try:
                data = response.json()
                print(f"   Response Type: {data.get('status', 'unknown')}")
                
                if response.status_code == 200:
                    if 'csrf_token' in data:
                        print(f"   ✅ SUCCESS - Got CSRF token")
                    else:
                        print(f"   ❓ UNEXPECTED - 200 but no CSRF token")
                        print(f"   Raw Response: {json.dumps(data, indent=2)}")
                
                elif response.status_code == 429:
                    print(f"   🚫 RATE LIMITED")
                    if 'rate_limit' in data:
                        rl = data['rate_limit']
                        print(f"   Limit: {rl.get('limit')}/{rl.get('window_seconds')}s")
                        print(f"   Retry After: {rl.get('retry_after_seconds')}s")
                
                else:
                    print(f"   ❓ UNEXPECTED STATUS: {response.status_code}")
                    print(f"   Raw Response: {json.dumps(data, indent=2)}")
                    
            except json.JSONDecodeError:
                print(f"   ❌ Invalid JSON response")
                print(f"   Raw Content: {response.text[:200]}...")
        
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
        
        # Small delay between requests
        time.sleep(0.5)
    
    print(f"\n🎯 Expected Behavior:")
    print(f"   - First 3 requests: HTTP 200 with CSRF tokens")
    print(f"   - 4th+ requests: HTTP 429 with rate limit error")

if __name__ == "__main__":
    test_csrf_rate_limiting()
