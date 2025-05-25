import asyncio
import httpx
import time
import json
import os

# Configuration
BASE_URL = "http://127.0.0.1:8080/api/v1"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "Testpassword1"
DATABASE_FILE = 'blog_api_db.json' # Needs to match the one in restapi.py

async def register_and_login(client: httpx.AsyncClient):
    """Registers a new user and logs them in, returning the token."""
    print(f"Attempting to register user: {TEST_USERNAME}")
    register_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
    try:
        register_response = await client.post(f"{BASE_URL}/register", json=register_data)
        register_response.raise_for_status() # Raise an exception for bad status codes
        register_result = register_response.json()
        print(f"Registration successful: {register_result.get('message')}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409: # Conflict, user already exists
            print(f"User '{TEST_USERNAME}' already exists, proceeding to login.")
        else:
            print(f"Registration failed with status {e.response.status_code}: {e.response.text}")
            return None
    except httpx.RequestError as e:
        print(f"Network error during registration: {e}")
        return None

    print(f"Attempting to login user: {TEST_USERNAME}")
    login_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
    try:
        login_response = await client.post(f"{BASE_URL}/login", json=login_data)
        login_response.raise_for_status()
        login_result = login_response.json()
        token = login_result.get("token")
        print(f"Login successful. Token received: {token[:10]}...") # Print first 10 chars
        return token
    except httpx.HTTPStatusError as e:
        print(f"Login failed with status {e.response.status_code}: {e.response.text}")
        return None
    except httpx.RequestError as e:
        print(f"Network error during login: {e}")
        return None

async def make_authenticated_request(client: httpx.AsyncClient, token: str):
    """Makes a request to a protected endpoint using the provided token."""
    headers = {"Authorization": f"Bearer {token}"}
    print(f"Attempting to create a post with token...")
    post_data = {
        "title": f"Test Post by {TEST_USERNAME} {time.time()}",
        "text": "This is a test post to check token validity."
    }
    try:
        response = await client.post(f"{BASE_URL}/posts", headers=headers, json=post_data)
        return response
    except httpx.RequestError as e:
        print(f"Network error during authenticated request: {e}")
        return None

async def test_token_expiration():
    """
    Tests the token expiration by:
    1. Registering/logging in to get a token.
    2. Making an immediate authenticated request (should succeed).
    3. Waiting for a duration longer than the token expiration.
    4. Making another authenticated request (should fail with 401).
    """
    # Clean up the database file before starting the test for a clean slate
    if os.path.exists(DATABASE_FILE):
        os.remove(DATABASE_FILE)
        print(f"Removed existing database file: {DATABASE_FILE}")

    async with httpx.AsyncClient() as client:
        token = await register_and_login(client)
        if not token:
            print("Failed to obtain token. Exiting test.")
            return

        # --- Test 1: Token should be valid immediately after login ---
        print("\n--- Test 1: Checking token validity immediately after login ---")
        response_initial = await make_authenticated_request(client, token)
        if response_initial and response_initial.status_code == 201:
            print(f"SUCCESS: Initial authenticated request (create post) succeeded (Status: {response_initial.status_code}).")
            print(f"Response: {json.dumps(response_initial.json(), indent=2)}")
        else:
            print(f"FAILURE: Initial authenticated request failed. Status: {response_initial.status_code if response_initial else 'N/A'}")
            print(f"Response: {response_initial.text if response_initial else 'No response'}")
            return # Abort if initial request fails

        # --- Test 2: Wait for token to expire and re-test ---
        # The TOKEN_EXPIRATION_MINUTES in restapi_for_test.py is set to 1 minute.
        # We wait a bit longer to ensure it expires.
        wait_time_seconds = 65 # 1 minute and 5 seconds
        print(f"\n--- Test 2: Waiting for {wait_time_seconds} seconds for token to expire ---")
        await asyncio.sleep(wait_time_seconds)

        print("\n--- Test 2: Checking token validity after expiration ---")
        response_after_expiration = await make_authenticated_request(client, token)

        if response_after_expiration and response_after_expiration.status_code == 401:
            print(f"SUCCESS: Authenticated request after expiration failed with 401 Unauthorized (Status: {response_after_expiration.status_code}).")
            print(f"Response: {response_after_expiration.json().get('message')}")
        else:
            print(f"FAILURE: Authenticated request after expiration did NOT fail with 401. Status: {response_after_expiration.status_code if response_after_expiration else 'N/A'}")
            print(f"Response: {response_after_expiration.text if response_after_expiration else 'No response'}")

if __name__ == "__main__":
    asyncio.run(test_token_expiration())
