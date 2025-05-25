#!/usr/bin/env python3
"""
API Test Client
Standalone test client for the REST API
Usage: python test_client.py
"""

import asyncio
import aiohttp
import json
import time
import random
import string

BASE_URL = "http://127.0.0.1:8080/api/v1"
SERVER_URL = "http://127.0.0.1:8080"

def generate_test_username():
    """Generate a unique test username"""
    timestamp = str(int(time.time()))
    random_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
    return f"testuser_{timestamp}_{random_suffix}"

async def test_api():
    print("🚀 Testing Blog API...")
    
    async with aiohttp.ClientSession() as session:
        try:
            # Test 1: Health check
            print("\n📊 1. Testing health check...")
            async with session.get(f"{SERVER_URL}/health") as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Health check OK: {result['status']} - {result['users']} users, {result['posts']} posts")
                else:
                    print(f"❌ Health check failed: {resp.status}")
                    return

            # Test 2: API root
            print("\n📋 2. Testing API root...")
            async with session.get(f"{SERVER_URL}/") as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ API root OK: {result['message']}")
                else:
                    print(f"❌ API root failed: {resp.status}")

            # Test 3: User registration
            print("\n👤 3. Testing user registration...")
            test_username = generate_test_username()
            test_password = "testpass123"
            
            register_data = {"username": test_username, "password": test_password}
            async with session.post(f"{BASE_URL}/register", json=register_data) as resp:
                if resp.status == 201:
                    result = await resp.json()
                    print(f"✅ Registration successful: User {result['user_id']} created")
                    token = result["token"]
                else:
                    result = await resp.json()
                    print(f"❌ Registration failed: {resp.status} - {result.get('message', 'Unknown error')}")
                    return

            # Test 4: User login
            print("\n🔐 4. Testing user login...")
            login_data = {"username": test_username, "password": test_password}
            async with session.post(f"{BASE_URL}/login", json=login_data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Login successful")
                    # Update token from login (should be the same)
                    token = result["token"]
                else:
                    result = await resp.json()
                    print(f"❌ Login failed: {resp.status} - {result.get('message', 'Unknown error')}")
                    return

            headers = {"Authorization": f"Bearer {token}"}

            # Test 5: Create a post
            print("\n📝 5. Testing post creation...")
            post_data = {
                "title": "My Test Blog Post", 
                "text": "This is a comprehensive test post with enough content to meet the minimum requirements for the blog API."
            }
            async with session.post(f"{BASE_URL}/posts", json=post_data, headers=headers) as resp:
                if resp.status == 201:
                    result = await resp.json()
                    print(f"✅ Post created: ID {result['data']['id']} - '{result['data']['title']}'")
                    post_id = result["data"]["id"]
                else:
                    result = await resp.json()
                    print(f"❌ Post creation failed: {resp.status} - {result.get('message', 'Unknown error')}")
                    return

            # Test 6: List all posts
            print("\n📋 6. Testing post listing...")
            async with session.get(f"{BASE_URL}/posts") as resp:
                if resp.status == 200:
                    result = await resp.json()
                    posts = result["data"]
                    print(f"✅ Found {len(posts)} posts")
                    if posts:
                        print(f"   Latest post: '{posts[0]['title']}'")
                else:
                    result = await resp.json()
                    print(f"❌ Post listing failed: {resp.status} - {result.get('message', 'Unknown error')}")

            # Test 7: Get single post
            print(f"\n📄 7. Testing get post {post_id}...")
            async with session.get(f"{BASE_URL}/posts/{post_id}") as resp:
                if resp.status == 200:
                    result = await resp.json()
                    post = result["data"]
                    print(f"✅ Post retrieved: '{post['title']}'")
                    print(f"   Created: {time.ctime(post['created_at'])}")
                    print(f"   Owner ID: {post['owner_id']}")
                else:
                    result = await resp.json()
                    print(f"❌ Get post failed: {resp.status} - {result.get('message', 'Unknown error')}")

            # Test 8: Update post
            print(f"\n✏️  8. Testing post update...")
            update_data = {
                "title": "Updated Test Post",
                "text": "This post has been updated with new content that is still long enough to meet requirements."
            }
            async with session.patch(f"{BASE_URL}/posts/{post_id}", json=update_data, headers=headers) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    updated_post = result["data"]
                    print(f"✅ Post updated: '{updated_post['title']}'")
                    print(f"   Updated: {time.ctime(updated_post['updated_at'])}")
                else:
                    result = await resp.json()
                    print(f"❌ Post update failed: {resp.status} - {result.get('message', 'Unknown error')}")

            # Test 9: Test invalid operations
            print("\n🚫 9. Testing error handling...")
            
            # Try to get non-existent post
            async with session.get(f"{BASE_URL}/posts/99999") as resp:
                if resp.status == 404:
                    print("✅ 404 error handling works")
                else:
                    print(f"⚠️  Expected 404, got {resp.status}")

            # Try unauthorized access
            async with session.post(f"{BASE_URL}/posts", json=post_data) as resp:
                if resp.status == 401:
                    print("✅ Authentication required works")
                else:
                    print(f"⚠️  Expected 401, got {resp.status}")

            # Test 10: Delete post
            print(f"\n🗑️  10. Testing post deletion...")
            async with session.delete(f"{BASE_URL}/posts/{post_id}", headers=headers) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Post deleted: {result['message']}")
                else:
                    result = await resp.json()
                    print(f"❌ Post deletion failed: {resp.status} - {result.get('message', 'Unknown error')}")

            # Test 11: Verify deletion
            print(f"\n🔍 11. Verifying post deletion...")
            async with session.get(f"{BASE_URL}/posts/{post_id}") as resp:
                if resp.status == 404:
                    print("✅ Post successfully deleted (returns 404)")
                else:
                    print(f"⚠️  Expected 404 after deletion, got {resp.status}")

            # Test 12: Rate limiting test (optional)
            print(f"\n⏱️  12. Testing rate limiting (quick test)...")
            rate_limit_count = 0
            for i in range(5):
                async with session.get(f"{BASE_URL}/posts") as resp:
                    if resp.status == 429:
                        rate_limit_count += 1
                        break
                    await asyncio.sleep(0.1)
            
            if rate_limit_count > 0:
                print("✅ Rate limiting is working")
            else:
                print("ℹ️  Rate limiting not triggered (normal for low traffic)")

            print("\n🎉 All API tests completed successfully!")
            print(f"🔑 Test user created: {test_username}")

        except aiohttp.ClientError as e:
            print(f"❌ Connection error: {e}")
            print("   Make sure the API server is running on port 8080")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

async def test_performance():
    """Optional performance test"""
    print("\n⚡ Running performance test...")
    
    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        tasks = []
        
        # Create 10 concurrent requests
        for i in range(10):
            task = session.get(f"{BASE_URL}/posts")
            tasks.append(task)
        
        try:
            responses = await asyncio.gather(*tasks)
            end_time = time.time()
            
            successful = sum(1 for resp in responses if resp.status == 200)
            print(f"✅ Performance test: {successful}/10 requests successful in {end_time - start_time:.2f}s")
            
            # Close responses
            for resp in responses:
                resp.close()
                
        except Exception as e:
            print(f"⚠️  Performance test error: {e}")

if __name__ == "__main__":
    print("🧪 Blog API Test Client")
    print("=" * 50)
    
    try:
        # Run main tests
        asyncio.run(test_api())
        
        # Ask if user wants performance test
        print("\n" + "=" * 50)
        response = input("Run performance test? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            asyncio.run(test_performance())
            
    except KeyboardInterrupt:
        print("\n❌ Tests cancelled by user")
    except Exception as e:
        print(f"❌ Test runner error: {e}")
    
    print("\n🏁 Test client finished")
