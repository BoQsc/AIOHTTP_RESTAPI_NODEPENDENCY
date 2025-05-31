# test_script.py
import preprocessor

# Override the default base URL to point at our local server:
BASE_URL = 'http://localhost:8000'

# 1) Create a new post (POST /posts)
POST /posts:
    json = {
        'title': 'foo',
        'body': 'bar',
        'userId': 1
    }
    headers = {'X-Demo': 'true'}
    max_retries = 2

# 2) Retrieve it (GET /posts/1)
GET /posts/1

# 3) Update it (PUT /posts/1)
PUT /posts/1:
    json = {
        'id': 1,
        'title': 'updated',
        'body': 'Hello Again',
        'userId': 1
    }

# 4) Delete it (DELETE /posts/1)
DELETE /posts/1

# 5) You can still run any normal Python here:
print("All HTTP calls have completed.")