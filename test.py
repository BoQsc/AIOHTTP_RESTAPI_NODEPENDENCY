import asyncio
import aiohttp
import json
import logging
import time

# --- Configuration for Test Client ---
API_BASE_URL = "http://127.0.0.1:8080" # Changed this
TEST_USERNAME = "testuser"
TEST_PASSWORD = "Password123"
TEST_USERNAME_2 = "anotheruser"
TEST_PASSWORD_2 = "Secret456"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BlogAPIClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = None # Will be initialized in async context
        self.token = None
        self.current_user_id = None
        self.headers = {"Content-Type": "application/json"}

    async def __aenter__(self):
        """Context manager to ensure aiohttp session is properly closed."""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager to ensure aiohttp session is properly closed."""
        if self.session:
            await self.session.close()

    def _get_auth_headers(self):
        """Returns headers with Authorization token if available."""
        if self.token:
            return {**self.headers, "Authorization": f"Bearer {self.token}"}
        return self.headers

    async def _make_request(self, method, endpoint, json_data=None, params=None, expected_status=200):
        """Helper to make HTTP requests and log results."""
        # Adjusted URL construction
        if endpoint == "/":
            url = f"{self.base_url}{endpoint}"
        else:
            url = f"{self.base_url}/api/v1{endpoint}" # Add /api/v1 for all other endpoints
            
        logger.info(f"--- Making {method} request to: {url} ---")
        logger.debug(f"JSON: {json_data}, Params: {params}, Headers: {self._get_auth_headers()}")

        try:
            async with self.session.request(method, url, json=json_data, params=params, headers=self._get_auth_headers()) as response:
                response_text = await response.text() # Get text first to avoid double read
                try:
                    response_json = json.loads(response_text)
                except json.JSONDecodeError:
                    response_json = {"error": "Invalid JSON response", "raw_response": response_text}

                logger.info(f"Response Status: {response.status}")
                logger.info(f"Response Body: {json.dumps(response_json, indent=2)}")

                if response.status == expected_status:
                    logger.info(f"Request successful (status {response.status}).")
                    return response_json
                else:
                    logger.error(f"Request failed: Expected {expected_status}, got {response.status}. Error: {response_json}")
                    return None
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection Error: Could not connect to {url}. Is the server running? Details: {e}")
            return None
        except Exception as e:
            logger.exception(f"An unexpected error occurred during request to {url}: {e}")
            return None

    # --- Authentication Endpoints ---
    async def register(self, username, password):
        logger.info(f"\n--- Registering user: {username} ---")
        data = {"username": username, "password": password}
        response = await self._make_request("POST", "/register", json_data=data, expected_status=201)
        if response and response.get("status") == "success":
            self.token = response.get("token")
            self.current_user_id = response.get("user_id")
            logger.info(f"Registration successful. Token: {self.token[:10]}... User ID: {self.current_user_id}")
            return True
        return False

    async def login(self, username, password):
        logger.info(f"\n--- Logging in user: {username} ---")
        data = {"username": username, "password": password}
        response = await self._make_request("POST", "/login", json_data=data)
        if response and response.get("status") == "success":
            self.token = response.get("token")
            # User ID is not returned by login, but we can decode it if needed
            # For this client, we just use the token for auth
            logger.info(f"Login successful. Token: {self.token[:10]}...")
            return True
        self.token = None
        self.current_user_id = None
        return False

    # --- Post Endpoints ---
    async def create_post(self, title, text):
        logger.info(f"\n--- Creating post: '{title}' ---")
        data = {"title": title, "text": text}
        response = await self._make_request("POST", "/posts", json_data=data, expected_status=201)
        if response and response.get("status") == "success":
            logger.info(f"Post created successfully. Post ID: {response['data']['id']}")
            return response['data']['id']
        return None

    async def list_posts(self, page=1, limit=10):
        logger.info(f"\n--- Listing posts (page={page}, limit={limit}) ---")
        params = {"page": page, "limit": limit}
        response = await self._make_request("GET", "/posts", params=params)
        if response and response.get("status") == "success":
            logger.info(f"Successfully listed {len(response['data'])} posts.")
            return response['data']
        return None

    async def get_post(self, post_id):
        logger.info(f"\n--- Getting post ID: {post_id} ---")
        response = await self._make_request("GET", f"/posts/{post_id}")
        if response and response.get("status") == "success":
            logger.info(f"Successfully retrieved post: '{response['data']['title']}'")
            return response['data']
        return None

    async def update_post(self, post_id, title=None, text=None):
        logger.info(f"\n--- Updating post ID: {post_id} ---")
        data = {}
        if title is not None:
            data["title"] = title
        if text is not None:
            data["text"] = text
        
        if not data:
            logger.warning("No data provided for post update.")
            return False

        response = await self._make_request("PATCH", f"/posts/{post_id}", json_data=data)
        if response and response.get("status") == "success":
            logger.info(f"Post {post_id} updated successfully.")
            return True
        return False

    async def delete_post(self, post_id):
        logger.info(f"\n--- Deleting post ID: {post_id} ---")
        response = await self._make_request("DELETE", f"/posts/{post_id}")
        if response and response.get("status") == "success":
            logger.info(f"Post {post_id} deleted successfully.")
            return True
        return False

    # --- Comment Endpoints ---
    async def create_comment(self, post_id, text):
        logger.info(f"\n--- Adding comment to post {post_id} ---")
        data = {"text": text}
        response = await self._make_request("POST", f"/posts/{post_id}/comments", json_data=data, expected_status=201)
        if response and response.get("status") == "success":
            logger.info(f"Comment created successfully. Comment ID: {response['data']['id']}")
            return response['data']['id']
        return None

    async def list_comments_for_post(self, post_id):
        logger.info(f"\n--- Listing comments for post {post_id} ---")
        response = await self._make_request("GET", f"/posts/{post_id}/comments")
        if response and response.get("status") == "success":
            logger.info(f"Successfully listed {len(response['data'])} comments for post {post_id}.")
            return response['data']
        return None

    async def update_comment(self, comment_id, text):
        logger.info(f"\n--- Updating comment ID: {comment_id} ---")
        data = {"text": text}
        response = await self._make_request("PATCH", f"/comments/{comment_id}", json_data=data)
        if response and response.get("status") == "success":
            logger.info(f"Comment {comment_id} updated successfully.")
            return True
        return False

    async def delete_comment(self, comment_id):
        logger.info(f"\n--- Deleting comment ID: {comment_id} ---")
        response = await self._make_request("DELETE", f"/comments/{comment_id}")
        if response and response.get("status") == "success":
            logger.info(f"Comment {comment_id} deleted successfully.")
            return True
        return False

async def run_tests():
    async with BlogAPIClient(API_BASE_URL) as client:
        logger.info("\n--- Starting API Tests ---")

        # --- Test 1: Root Endpoint ---
        logger.info("\n=== Test 1: Get Root API Info ===")
        await client._make_request("GET", "/", expected_status=200)

        # --- Test 2: User Registration (Primary User) ---
        logger.info("\n=== Test 2: User Registration (Primary) ===")
        registered = await client.register(TEST_USERNAME, TEST_PASSWORD)
        assert registered, "Test 2 Failed: Primary user registration failed."
        primary_user_token = client.token
        primary_user_id = client.current_user_id

        # --- Test 3: Attempt to register same user (should fail) ---
        logger.info("\n=== Test 3: Attempt to Register Existing User ===")
        client.token = None # Clear token for this test
        await client.register(TEST_USERNAME, TEST_PASSWORD) # Expected to fail with 409
        assert client.token is None, "Test 3 Failed: Re-registering user unexpectedly succeeded."
        client.token = primary_user_token # Restore token

        # --- Test 4: User Login (Primary User) ---
        logger.info("\n=== Test 4: User Login (Primary) ===")
        client.token = None # Ensure we re-login
        logged_in = await client.login(TEST_USERNAME, TEST_PASSWORD)
        assert logged_in, "Test 4 Failed: Primary user login failed."
        assert client.token is not None, "Test 4 Failed: No token received after login."

        # --- Test 5: User Registration (Secondary User) ---
        logger.info("\n=== Test 5: User Registration (Secondary) ===")
        # Use a new client instance or clear token for second user
        async with BlogAPIClient(API_BASE_URL) as client2:
            registered2 = await client2.register(TEST_USERNAME_2, TEST_PASSWORD_2)
            assert registered2, "Test 5 Failed: Secondary user registration failed."
            secondary_user_token = client2.token

        # Restore primary user's context
        client.token = primary_user_token
        
        # --- Test 6: Create Post (Primary User) ---
        logger.info("\n=== Test 6: Create Post ===")
        post_id = await client.create_post("My First Blog Post", "This is the exciting content of my very first blog post. Hope you enjoy it!")
        assert post_id is not None, "Test 6 Failed: Post creation failed."

        post_id_2 = await client.create_post("A Second Post", "More interesting stuff here.")
        assert post_id_2 is not None, "Test 6 Failed: Second post creation failed."

        # --- Test 7: List Posts ---
        logger.info("\n=== Test 7: List Posts ===")
        posts = await client.list_posts(page=1, limit=5)
        assert posts is not None and len(posts) >= 2, "Test 7 Failed: Listing posts failed or incorrect count."
        assert any(p['id'] == post_id for p in posts), "Test 7 Failed: First created post not found in list."

        # --- Test 8: Get Single Post ---
        logger.info("\n=== Test 8: Get Single Post ===")
        retrieved_post = await client.get_post(post_id)
        assert retrieved_post is not None and retrieved_post['id'] == post_id, "Test 8 Failed: Retrieving single post failed."
        assert retrieved_post['title'] == "My First Blog Post", "Test 8 Failed: Retrieved post title mismatch."

        # --- Test 9: Update Post (Owner) ---
        logger.info("\n=== Test 9: Update Post (Owner) ===")
        updated = await client.update_post(post_id, title="My Updated First Post", text="This is the updated content.")
        assert updated, "Test 9 Failed: Post update by owner failed."
        check_updated_post = await client.get_post(post_id)
        assert check_updated_post['title'] == "My Updated First Post", "Test 9 Failed: Post title not updated."

        # --- Test 10: Attempt to Update Another User's Post (should fail 403) ---
        logger.info("\n=== Test 10: Update Another User's Post (Expected Fail) ===")
        # Create a post with the second user
        async with BlogAPIClient(API_BASE_URL) as client2:
            client2.token = secondary_user_token
            second_user_post_id = await client2.create_post("Second User's Post", "Content by another user.")
            assert second_user_post_id is not None, "Failed to create post for secondary user."

        # Try to update it with the primary user's token
        client.token = primary_user_token # Ensure current client has primary token
        failed_update = await client._make_request("PATCH", f"/posts/{second_user_post_id}", 
                                                    json_data={"title": "Trying to hack"}, expected_status=403)
        assert failed_update is not None, "Test 10 Failed: Update of another user's post should have returned a response."
        assert failed_update.get("status") == "error" and "You can only edit your own posts" in failed_update.get("message"), \
            "Test 10 Failed: Incorrect error for unauthorized post update."


        # --- Test 11: Create Comment ---
        logger.info("\n=== Test 11: Create Comment ===")
        comment_id = await client.create_comment(post_id, "This is a great post!")
        assert comment_id is not None, "Test 11 Failed: Comment creation failed."

        # --- Test 12: List Comments for Post ---
        logger.info("\n=== Test 12: List Comments for Post ===")
        comments = await client.list_comments_for_post(post_id)
        assert comments is not None and len(comments) >= 1, "Test 12 Failed: Listing comments failed."
        assert any(c['id'] == comment_id for c in comments), "Test 12 Failed: Created comment not found in list."

        # --- Test 13: Update Comment (Owner) ---
        logger.info("\n=== Test 13: Update Comment (Owner) ===")
        updated_comment = await client.update_comment(comment_id, "This is an updated comment!")
        assert updated_comment, "Test 13 Failed: Comment update by owner failed."

        # --- Test 14: Delete Comment (Owner) ---
        logger.info("\n=== Test 14: Delete Comment (Owner) ===")
        deleted_comment = await client.delete_comment(comment_id)
        assert deleted_comment, "Test 14 Failed: Comment deletion by owner failed."
        # Verify it's gone
        comments_after_delete = await client.list_comments_for_post(post_id)
        assert all(c['id'] != comment_id for c in comments_after_delete), "Test 14 Failed: Comment still exists after deletion."

        # --- Test 15: Delete Post (Owner) ---
        logger.info("\n=== Test 15: Delete Post (Owner) ===")
        deleted_post = await client.delete_post(post_id)
        assert deleted_post, "Test 15 Failed: Post deletion by owner failed."
        # Verify it's gone
        check_deleted_post = await client.get_post(post_id) # Should return 404
        assert check_deleted_post is None, "Test 15 Failed: Post still exists after deletion."
        
        # Test that comments associated with the deleted post are also gone
        # When a post is deleted, listing its comments should result in a 404
        comments_for_deleted_post = await client._make_request("GET", f"/posts/{post_id}/comments", expected_status=404)
        assert comments_for_deleted_post is not None, "Test 15 Failed: Request for comments on deleted post should have returned an error response."
        assert comments_for_deleted_post.get("status") == "error" and "not found" in comments_for_deleted_post.get("message").lower(), \
            "Test 15 Failed: Comments for deleted post returned unexpected response."


        # --- Test 16: Unauthorized Access (No Token) ---
        logger.info("\n=== Test 16: Unauthorized Access (No Token) ===")
        original_token = client.token
        client.token = None # Clear token
        failed_create = await client._make_request("POST", "/posts", json_data={"title": "No Auth", "text": "Should fail"}, expected_status=401)
        assert failed_create is not None, "Test 16 Failed: Unauthorized request unexpectedly succeeded."
        assert failed_create.get("status") == "error" and "Authentication required" in failed_create.get("message"), \
            "Test 16 Failed: Incorrect error for unauthorized post creation."
        client.token = original_token # Restore token


        logger.info("\n--- All API Tests Completed Successfully! ---")
        
if __name__ == "__main__":
    # To run this client, ensure your blog_api.py server is running first.
    # Open a terminal, run: python blog_api.py
    # Then, in another terminal, run: python test_client.py
    asyncio.run(run_tests())