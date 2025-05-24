import requests
import json
import time
import sys

# --- Configuration ---
BASE_URL = "http://localhost:8080"
API_VERSION = "/api/v1"
API_BASE_URL = f"{BASE_URL}{API_VERSION}"

# --- ANSI Color Codes for Output ---
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"
FAINT = "\033[2m"

# --- Helper Functions ---

def print_test_header(title: str):
    """Prints a formatted header for a test section."""
    print(f"\n{BOLD}{BLUE}--- {title} ---{RESET}")

def print_request(method: str, url: str, headers: dict = None, data: dict = None):
    """Prints details of the outgoing request."""
    print(f"{FAINT}  {method} {url}{RESET}")
    if headers:
        print(f"{FAINT}  Headers: {json.dumps(headers)}{RESET}")
    if data:
        print(f"{FAINT}  Body: {json.dumps(data)}{RESET}")

def print_response(response: requests.Response, expected_status: int = 200):
    """Prints response details and indicates success/failure."""
    status_color = GREEN if response.status_code == expected_status else RED
    print(f"  {BOLD}Status: {status_color}{response.status_code}{RESET} (Expected: {expected_status})")
    try:
        response_json = response.json()
        print(f"  {BOLD}Response Body:{RESET} {json.dumps(response_json, indent=2)}")
    except json.JSONDecodeError:
        print(f"  {BOLD}Response Body:{RESET} {response.text[:200]}...") # Print partial text for non-JSON
    
    if response.status_code == expected_status:
        print(f"  {GREEN}Test Passed!{RESET}")
        return True
    else:
        print(f"  {RED}Test Failed!{RESET}")
        return False

# --- Test Functions for Each Endpoint ---

def test_root_endpoint():
    """Tests the root endpoint."""
    print_test_header("Testing Root Endpoint")
    url = BASE_URL + "/"
    print_request("GET", url)
    response = requests.get(url)
    return print_response(response, 200)

def test_register_user(username, password):
    """Registers a new user and returns their token."""
    print_test_header(f"Testing User Registration: {username}")
    url = f"{API_BASE_URL}/register"
    data = {"username": username, "password": password}
    print_request("POST", url, data=data)
    response = requests.post(url, json=data)
    if print_response(response, 201):
        return response.json().get("token")
    return None

def test_register_existing_user(username, password):
    """Tests registering a user that already exists."""
    print_test_header(f"Testing Registration of Existing User: {username}")
    url = f"{API_BASE_URL}/register"
    data = {"username": username, "password": password}
    print_request("POST", url, data=data)
    response = requests.post(url, json=data)
    return print_response(response, 400) # Expecting BadRequestError

def test_login_user(username, password):
    """Logs in a user and returns their token."""
    print_test_header(f"Testing User Login: {username}")
    url = f"{API_BASE_URL}/login"
    data = {"username": username, "password": password}
    print_request("POST", url, data=data)
    response = requests.post(url, json=data)
    if print_response(response, 200):
        return response.json().get("token")
    return None

def test_login_invalid_credentials(username, password):
    """Tests login with invalid credentials."""
    print_test_header(f"Testing Login with Invalid Credentials: {username}")
    url = f"{API_BASE_URL}/login"
    data = {"username": username, "password": password}
    print_request("POST", url, data=data)
    response = requests.post(url, json=data)
    return print_response(response, 401) # Expecting UnauthorizedError

def test_create_post(token, title, text):
    """Creates a new post."""
    print_test_header(f"Testing Create Post: '{title}'")
    url = f"{API_BASE_URL}/posts"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"title": title, "text": text}
    print_request("POST", url, headers=headers, data=data)
    response = requests.post(url, headers=headers, json=data)
    if print_response(response, 201):
        return response.json().get("data", {}).get("id")
    return None

def test_create_post_unauthorized(title, text):
    """Tests creating a post without authentication."""
    print_test_header("Testing Create Post (Unauthorized)")
    url = f"{API_BASE_URL}/posts"
    data = {"title": title, "text": text}
    # No Authorization header for unauthorized test
    print_request("POST", url, data=data)
    response = requests.post(url, json=data)
    return print_response(response, 401) # Expecting UnauthorizedError

def test_create_post_invalid_input(token, title, text):
    """Tests creating a post with invalid input."""
    print_test_header("Testing Create Post (Invalid Input)")
    url = f"{API_BASE_URL}/posts"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"title": title, "text": text}
    print_request("POST", url, headers=headers, data=data)
    response = requests.post(url, headers=headers, json=data)
    return print_response(response, 400) # Expecting BadRequestError

def test_list_posts():
    """Lists all posts."""
    print_test_header("Testing List Posts")
    url = f"{API_BASE_URL}/posts"
    print_request("GET", url)
    response = requests.get(url)
    return print_response(response, 200)

def test_get_post(post_id):
    """Retrieves a specific post."""
    print_test_header(f"Testing Get Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    print_request("GET", url)
    response = requests.get(url)
    return print_response(response, 200)

def test_get_non_existent_post(post_id):
    """Tests retrieving a non-existent post."""
    print_test_header(f"Testing Get Non-Existent Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    print_request("GET", url)
    response = requests.get(url)
    return print_response(response, 404) # Expecting NotFoundError

def test_update_post(token, post_id, title=None, text=None):
    """Updates a specific post."""
    print_test_header(f"Testing Update Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    data = {}
    if title is not None:
        data["title"] = title
    if text is not None:
        data["text"] = text
    
    print_request("PATCH", url, headers=headers, data=data)
    response = requests.patch(url, headers=headers, json=data)
    return print_response(response, 200)

def test_update_post_unauthorized(post_id, title="Unauthorized Update"):
    """Tests updating a post without authentication."""
    print_test_header(f"Testing Update Post (Unauthorized): {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    data = {"title": title}
    # No Authorization header for unauthorized test
    print_request("PATCH", url, data=data)
    response = requests.patch(url, json=data)
    return print_response(response, 401) # Expecting UnauthorizedError

def test_update_post_forbidden(token, post_id, title="Forbidden Update"):
    """Tests updating a post owned by another user."""
    print_test_header(f"Testing Update Post (Forbidden): {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"title": title}
    print_request("PATCH", url, headers=headers, data=data)
    response = requests.patch(url, headers=headers, json=data)
    return print_response(response, 403) # Expecting ForbiddenError

def test_update_non_existent_post(token, post_id, title="Non Existent Update"):
    """Tests updating a non-existent post."""
    print_test_header(f"Testing Update Non-Existent Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"title": title}
    print_request("PATCH", url, headers=headers, data=data)
    response = requests.patch(url, headers=headers, json=data)
    return print_response(response, 404) # Expecting NotFoundError

def test_delete_post(token, post_id):
    """Deletes a specific post."""
    print_test_header(f"Testing Delete Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    print_request("DELETE", url, headers=headers)
    response = requests.delete(url, headers=headers)
    return print_response(response, 200)

def test_delete_post_unauthorized(post_id):
    """Tests deleting a post without authentication."""
    print_test_header(f"Testing Delete Post (Unauthorized): {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    # No Authorization header for unauthorized test
    print_request("DELETE", url)
    response = requests.delete(url)
    return print_response(response, 401) # Expecting UnauthorizedError

def test_delete_post_forbidden(token, post_id):
    """Tests deleting a post owned by another user."""
    print_test_header(f"Testing Delete Post (Forbidden): {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    print_request("DELETE", url, headers=headers)
    response = requests.delete(url, headers=headers)
    return print_response(response, 403) # Expecting ForbiddenError

def test_delete_non_existent_post(token, post_id):
    """Tests deleting a non-existent post."""
    print_test_header(f"Testing Delete Non-Existent Post: {post_id}")
    url = f"{API_BASE_URL}/posts/{post_id}"
    headers = {"Authorization": f"Bearer {token}"}
    print_request("DELETE", url, headers=headers)
    response = requests.delete(url, headers=headers)
    return print_response(response, 404) # Expecting NotFoundError

# --- Main Test Execution ---

def run_all_tests():
    """Orchestrates the execution of all API tests."""
    print(f"{BOLD}{YELLOW}--- Starting API Test Client ---{RESET}")

    # Ensure the server is running
    try:
        requests.get(BASE_URL)
        print(f"{GREEN}Server is reachable at {BASE_URL}{RESET}")
    except requests.exceptions.ConnectionError:
        print(f"{RED}Error: Could not connect to the server at {BASE_URL}. Please ensure the AIOHTTP server is running.{RESET}")
        sys.exit(1)

    # --- Public Endpoints ---
    test_root_endpoint()
    test_list_posts() # Should be empty initially

    # --- User Management ---
    user1_username = "testuser1"
    user1_password = "password123"
    user2_username = "testuser2"
    user2_password = "securepassword"

    user1_token = test_register_user(user1_username, user1_password)
    test_register_existing_user(user1_username, user1_password) # Should fail (400)

    user2_token = test_register_user(user2_username, user2_password)
    test_login_invalid_credentials(user1_username, "wrongpassword") # Should fail (401)
    # Re-login user1 to get a fresh token if needed (e.g., if token expired during long test run)
    user1_token = test_login_user(user1_username, user1_password)
    
    if not user1_token or not user2_token:
        print(f"{RED}Failed to obtain user tokens. Aborting further tests.{RESET}")
        sys.exit(1)

    # --- Post Management (Authenticated) ---
    post1_id = test_create_post(user1_token, "My First Post", "This is the content of my very first post.")
    test_create_post_unauthorized("Unauthorized Post", "This post should not be created.") # Should fail (401)
    test_create_post_invalid_input(user1_token, "Short", "too short") # Should fail (400 - text too short)
    test_create_post_invalid_input(user1_token, "A" * 300, "This title is way too long for the validation rules.") # Should fail (400 - title too long)


    post2_id = test_create_post(user2_token, "User2's Post", "This post belongs to the second user.")

    # List posts again to see new posts
    test_list_posts()

    # Get specific posts
    if post1_id:
        test_get_post(post1_id)
    if post2_id:
        test_get_post(post2_id)
    test_get_non_existent_post(9999) # Should fail (404)

    # Update posts
    if post1_id:
        test_update_post(user1_token, post1_id, title="Updated Title for Post 1")
        test_update_post(user1_token, post1_id, text="Updated content for Post 1, much better now.")
        test_update_post(user1_token, post1_id, title="Final Title", text="Final content.")
        test_update_post_unauthorized(post1_id, "Attempt to update without auth") # Should fail (401)
        test_update_post_forbidden(user2_token, post1_id, "User2 trying to update User1's post") # Should fail (403)
        test_update_non_existent_post(user1_token, 9999, "Non-existent update") # Should fail (404)

    # Delete posts
    if post1_id:
        test_delete_post_unauthorized(post1_id) # Should fail (401)
        test_delete_post_forbidden(user2_token, post1_id) # Should fail (403)
        test_delete_non_existent_post(user1_token, 9999) # Should fail (404)
        test_delete_post(user1_token, post1_id) # Should succeed (200)

    # Verify deletion
    if post1_id:
        test_get_non_existent_post(post1_id) # Should now be 404

    # Delete the second post
    if post2_id:
        test_delete_post(user2_token, post2_id)

    print(f"\n{BOLD}{YELLOW}--- All API Tests Completed ---{RESET}")

if __name__ == "__main__":
    run_all_tests()