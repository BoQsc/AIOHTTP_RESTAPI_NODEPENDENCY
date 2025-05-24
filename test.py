import asyncio
import aiohttp
import json
import os
import sys

# --- Configuration ---
BASE_URL = "http://localhost:8080"
TEST_USERS = [
    {"username": "testuser1", "password": "password123"},
    {"username": "testuser2", "password": "securepassword"}
]

# ANSI Escape Codes for coloring and formatting output
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_RED = "\033[91m"
COLOR_GREY = "\033[2m"

# Store tokens for test users
user_tokens = {}
user_ids = {}

# Store created post IDs for later use
created_post_ids = []
created_comment_ids = []

async def make_request(method, url, headers=None, json_data=None, expected_status=200):
    """Helper to make HTTP requests and print results."""
    print(f"{COLOR_GREY}  {method} {url}{COLOR_RESET}")
    if json_data:
        print(f"{COLOR_GREY}  Body: {json.dumps(json_data)}{COLOR_RESET}")
    if headers:
        print(f"{COLOR_GREY}  Headers: {json.dumps(headers)}{COLOR_RESET}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.request(method, url, headers=headers, json=json_data) as response:
                status = response.status
                response_body = await response.json() if response.content_type == 'application/json' else await response.text()

                print(f"  {COLOR_BOLD}Status: {COLOR_GREEN if status == expected_status else COLOR_RED}{status}{COLOR_RESET} (Expected: {expected_status})")
                print(f"  {COLOR_BOLD}Response Body:{COLOR_RESET} {json.dumps(response_body, indent=2)}")

                if status == expected_status:
                    print(f"  {COLOR_GREEN}Test Passed!{COLOR_RESET}\n")
                    return response_body, True
                else:
                    print(f"  {COLOR_RED}Test FAILED!{COLOR_RESET}\n")
                    return response_body, False
        except aiohttp.ClientConnectorError as e:
            print(f"  {COLOR_RED}Client Connector Error: Could not connect to the server at {url}. Is it running?{COLOR_RESET}")
            print(f"  Error details: {e}")
            sys.exit(1) # Exit if server is not reachable
        except json.JSONDecodeError:
            print(f"  {COLOR_RED}JSON Decode Error: Response was not valid JSON.{COLOR_RESET}")
            print(f"  Response Content: {response_body}")
            print(f"  {COLOR_RED}Test FAILED!{COLOR_RESET}\n")
            return None, False
        except Exception as e:
            print(f"  {COLOR_RED}An unexpected error occurred during the request: {e}{COLOR_RESET}")
            print(f"  {COLOR_RED}Test FAILED!{COLOR_RESET}\n")
            return None, False


async def run_tests():
    print(f"{COLOR_BOLD}{COLOR_YELLOW}--- Starting API Test Client ---{COLOR_RESET}")

    # --- Check Server Reachability ---
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(BASE_URL) as response:
                if response.status == 200:
                    print(f"{COLOR_GREEN}Server is reachable at {BASE_URL}{COLOR_RESET}\n")
                else:
                    print(f"{COLOR_RED}Server responded with status {response.status} at {BASE_URL}. Is it running correctly?{COLOR_RESET}")
                    sys.exit(1)
    except aiohttp.ClientConnectorError:
        print(f"{COLOR_RED}ERROR: Could not connect to the server at {BASE_URL}. Please ensure the server (blog_api.py) is running.{COLOR_RESET}")
        sys.exit(1)

    # --- Test Root Endpoint ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Root Endpoint ---{COLOR_RESET}")
    _, success = await make_request('GET', BASE_URL, expected_status=200)
    if not success: return

    # --- Test List Posts (Initially Empty) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Posts (Initially Empty) ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts", expected_status=200)
    if not success or response.get('data') is None or len(response['data']) != 0:
        print(f"  {COLOR_RED}Initial List Posts Test FAILED: Expected empty list.{COLOR_RESET}")
        return

    # --- Test User Registration ---
    for user_data in TEST_USERS:
        print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing User Registration: {user_data['username']} ---{COLOR_RESET}")
        response, success = await make_request(
            'POST', f"{BASE_URL}/api/v1/register",
            json_data=user_data,
            expected_status=201
        )
        if not success: return
        user_tokens[user_data['username']] = response['token']
        user_ids[user_data['username']] = response['user_id']

    # --- Test Registration of Existing User ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Registration of Existing User: {TEST_USERS[0]['username']} ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/register",
        json_data=TEST_USERS[0],
        expected_status=400
    )

    # --- Test Login with Invalid Credentials ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Login with Invalid Credentials: {TEST_USERS[0]['username']} ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/login",
        json_data={"username": TEST_USERS[0]['username'], "password": "wrongpassword"},
        expected_status=401
    )

    # --- Test User Login (Successful) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing User Login: {TEST_USERS[0]['username']} ---{COLOR_RESET}")
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/login",
        json_data={"username": TEST_USERS[0]['username'], "password": TEST_USERS[0]['password']},
        expected_status=200
    )
    if not success: return
    user_tokens[TEST_USERS[0]['username']] = response['token'] # Update token in case it changed

    # --- Test Create Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post: 'My First Post' ---{COLOR_RESET}")
    post_data_1 = {"title": "My First Post", "text": "This is the content of my very first post."}
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data=post_data_1,
        expected_status=201
    )
    if not success: return
    post_id_1 = response['data']['id']
    created_post_ids.append(post_id_1)

    # --- Test Create Post (Unauthorized) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post (Unauthorized) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        json_data={"title": "Unauthorized Post", "text": "This post should not be created."},
        expected_status=401
    )

    # --- Test Create Post (Invalid Input - Text Too Short) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post (Invalid Input - Text Too Short) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "Short", "text": "too short"},
        expected_status=400
    )

    # --- Test Create Post (Invalid Input - Title Too Long) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post (Invalid Input - Title Too Long) ---{COLOR_RESET}")
    long_title = "A" * 256 # Exceeds 255 character limit
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": long_title, "text": "This title is way too long for the validation rules."},
        expected_status=400
    )
    
    # --- Test Create Post (Invalid Input - Empty Title/Text) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post (Invalid Input - Empty Title) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "", "text": "This post should fail due to empty title."},
        expected_status=400
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post (Invalid Input - Empty Text) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "Valid Title", "text": ""},
        expected_status=400
    )

    # --- Test Create Post by User2 ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Post: 'User2's Post' ---{COLOR_RESET}")
    post_data_2 = {"title": "User2's Post", "text": "This post belongs to the second user."}
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/posts",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        json_data=post_data_2,
        expected_status=201
    )
    if not success: return
    post_id_2 = response['data']['id']
    created_post_ids.append(post_id_2)

    # --- Test List Posts (with content) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Posts (with content) ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts", expected_status=200)
    if not success or len(response.get('data', [])) != 2:
        print(f"  {COLOR_RED}List Posts Test FAILED: Expected 2 posts.{COLOR_RESET}")
        return

    # --- Test List Posts with Pagination ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Posts with Pagination (page 1, limit 1) ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts?page=1&limit=1", expected_status=200)
    if not success or len(response.get('data', [])) != 1 or response.get('total_posts') != 2:
        print(f"  {COLOR_RED}Pagination Test FAILED: Expected 1 post on page 1.{COLOR_RESET}")
        return

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Posts with Pagination (page 2, limit 1) ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts?page=2&limit=1", expected_status=200)
    if not success or len(response.get('data', [])) != 1 or response.get('total_posts') != 2:
        print(f"  {COLOR_RED}Pagination Test FAILED: Expected 1 post on page 2.{COLOR_RESET}")
        return

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Posts with Pagination (page 3, limit 1 - out of bounds) ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts?page=3&limit=1", expected_status=200)
    if not success or len(response.get('data', [])) != 0:
        print(f"  {COLOR_RED}Pagination Test FAILED: Expected 0 posts on out-of-bounds page.{COLOR_RESET}")
        return

    # --- Test Get Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Get Post: {post_id_1} ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_1}", expected_status=200)
    if not success or response['data']['id'] != post_id_1:
        print(f"  {COLOR_RED}Get Post Test FAILED for ID {post_id_1}.{COLOR_RESET}")
        return

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Get Post: {post_id_2} ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_2}", expected_status=200)
    if not success or response['data']['id'] != post_id_2:
        print(f"  {COLOR_RED}Get Post Test FAILED for ID {post_id_2}.{COLOR_RESET}")
        return

    # --- Test Get Non-Existent Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Get Non-Existent Post: 9999 ---{COLOR_RESET}")
    await make_request('GET', f"{BASE_URL}/api/v1/posts/9999", expected_status=404)

    # --- Test Update Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post: {post_id_1} (Title Only) ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "Updated Title for Post 1"},
        expected_status=200
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post: {post_id_1} (Text Only) ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "Updated content for Post 1, much better now."},
        expected_status=200
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post: {post_id_1} (Both Title & Text) ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "Final Title", "text": "Final content. This has been fully updated."},
        expected_status=200
    )

    # --- Test Update Post (Unauthorized) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post (Unauthorized): {post_id_1} ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        json_data={"title": "Attempt to update without auth"},
        expected_status=401
    )

    # --- Test Update Post (Forbidden - User2 trying to update User1's post) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post (Forbidden): {post_id_1} ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        json_data={"title": "User2 trying to update User1's post"},
        expected_status=403
    )

    # --- Test Update Non-Existent Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Non-Existent Post: 9999 ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/9999",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": "Non-existent update"},
        expected_status=404
    )
    
    # --- Test Update Post (Invalid Input - Text Too Short) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post (Invalid Input - Text Too Short) ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "short"},
        expected_status=400
    )

    # --- Test Update Post (Invalid Input - Title Too Long) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Post (Invalid Input - Title Too Long) ---{COLOR_RESET}")
    long_title = "B" * 256
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"title": long_title},
        expected_status=400
    )


    # --- Test Comment Functionality ---

    # --- Test Create Comment ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Comment on Post {post_id_1} ---{COLOR_RESET}")
    comment_data_1 = {"text": "This is a comment on the first post by user1."}
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data=comment_data_1,
        expected_status=201
    )
    if not success: return
    comment_id_1 = response['data']['id']
    created_comment_ids.append(comment_id_1)

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Another Comment on Post {post_id_1} by User2 ---{COLOR_RESET}")
    comment_data_2 = {"text": "User2 adds another comment to post 1."}
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        json_data=comment_data_2,
        expected_status=201
    )
    if not success: return
    comment_id_2 = response['data']['id']
    created_comment_ids.append(comment_id_2)


    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Comment on Post {post_id_2} ---{COLOR_RESET}")
    comment_data_3 = {"text": "A comment on the second post."}
    response, success = await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/{post_id_2}/comments",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        json_data=comment_data_3,
        expected_status=201
    )
    if not success: return
    comment_id_3 = response['data']['id']
    created_comment_ids.append(comment_id_3)

    # --- Test Create Comment (Unauthorized) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Comment (Unauthorized) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments",
        json_data={"text": "Unauthorized comment."},
        expected_status=401
    )

    # --- Test Create Comment (Invalid Input - Text Too Short) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Comment (Invalid Input - Text Too Short) ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "hi"},
        expected_status=400
    )

    # --- Test Create Comment on Non-Existent Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Create Comment on Non-Existent Post: 9999 ---{COLOR_RESET}")
    await make_request(
        'POST', f"{BASE_URL}/api/v1/posts/9999/comments",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "This comment should fail."},
        expected_status=404
    )

    # --- Test List Comments for Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Comments for Post {post_id_1} ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments", expected_status=200)
    if not success or len(response.get('data', [])) != 2:
        print(f"  {COLOR_RED}List Comments Test FAILED for Post {post_id_1}: Expected 2 comments.{COLOR_RESET}")
        return

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Comments for Post {post_id_2} ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_2}/comments", expected_status=200)
    if not success or len(response.get('data', [])) != 1:
        print(f"  {COLOR_RED}List Comments Test FAILED for Post {post_id_2}: Expected 1 comment.{COLOR_RESET}")
        return

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing List Comments for Non-Existent Post: 9999 ---{COLOR_RESET}")
    await make_request('GET', f"{BASE_URL}/api/v1/posts/9999/comments", expected_status=404)

    # --- Test Update Comment ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Comment: {comment_id_1} ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "Updated comment text by user1."},
        expected_status=200
    )

    # --- Test Update Comment (Unauthorized - User2 trying to update User1's comment) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Comment (Unauthorized): {comment_id_1} ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        json_data={"text": "User2 trying to update User1's comment."},
        expected_status=403
    )

    # --- Test Update Non-Existent Comment ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Non-Existent Comment: 9999 ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/comments/9999",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "Non-existent comment update."},
        expected_status=404
    )
    
    # --- Test Update Comment (Invalid Input - Text Too Short) ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Update Comment (Invalid Input - Text Too Short) ---{COLOR_RESET}")
    await make_request(
        'PATCH', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        json_data={"text": "no"},
        expected_status=400
    )


    # --- Test Delete Comment ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Comment (Unauthorized): {comment_id_1} ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        expected_status=401
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Comment (Forbidden): {comment_id_1} ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"}, # User 2 trying to delete user 1's comment
        expected_status=403
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Non-Existent Comment: 9999 ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/comments/9999",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        expected_status=404
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Comment: {comment_id_1} ---{COLOR_RESET}")
    response, success = await make_request(
        'DELETE', f"{BASE_URL}/api/v1/comments/{comment_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        expected_status=200
    )
    if not success: return

    # Verify comment is gone
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Verifying Comment {comment_id_1} is deleted ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments", expected_status=200)
    if not success or any(c['id'] == comment_id_1 for c in response.get('data', [])):
        print(f"  {COLOR_RED}Comment {comment_id_1} was not deleted.{COLOR_RESET}")
        return

    # --- Test Delete Post ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Post (Unauthorized): {post_id_1} ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        expected_status=401
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Post (Forbidden): {post_id_1} ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        expected_status=403
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Non-Existent Post: 9999 ---{COLOR_RESET}")
    await make_request(
        'DELETE', f"{BASE_URL}/api/v1/posts/9999",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        expected_status=404
    )

    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Post: {post_id_1} ---{COLOR_RESET}")
    response, success = await make_request(
        'DELETE', f"{BASE_URL}/api/v1/posts/{post_id_1}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[0]['username']]}"},
        expected_status=200
    )
    if not success: return

    # Verify post is gone
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Verifying Post {post_id_1} is deleted ---{COLOR_RESET}")
    await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_1}", expected_status=404)
    
    # Verify comments associated with post_id_1 are also gone
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Verifying Comments for Post {post_id_1} are deleted ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_1}/comments", expected_status=404) # Should return 404 as post is gone

    # --- Test Delete Post: {post_id_2} ---
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Testing Delete Post: {post_id_2} ---{COLOR_RESET}")
    response, success = await make_request(
        'DELETE', f"{BASE_URL}/api/v1/posts/{post_id_2}",
        headers={"Authorization": f"Bearer {user_tokens[TEST_USERS[1]['username']]}"},
        expected_status=200
    )
    if not success: return

    # Verify post is gone
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Verifying Post {post_id_2} is deleted ---{COLOR_RESET}")
    await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_2}", expected_status=404)

    # Verify comments associated with post_id_2 are also gone
    print(f"{COLOR_BOLD}{COLOR_BLUE}--- Verifying Comments for Post {post_id_2} are deleted ---{COLOR_RESET}")
    response, success = await make_request('GET', f"{BASE_URL}/api/v1/posts/{post_id_2}/comments", expected_status=404) # Should return 404 as post is gone


    print(f"{COLOR_BOLD}{COLOR_YELLOW}--- All API Tests Completed ---{COLOR_RESET}")


if __name__ == "__main__":
    # Remove the database file before running tests to ensure a clean state
    db_file = 'blog_api_db.json'
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"{COLOR_YELLOW}Cleaned up '{db_file}' before running tests.{COLOR_RESET}\n")

    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}Tests interrupted by user.{COLOR_RESET}")
    except Exception as e:
        print(f"\n{COLOR_RED}An unhandled error occurred during tests: {e}{COLOR_RESET}")