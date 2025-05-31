import preprocessor

BASE_URL = 'http://localhost:8000'

POST /posts:
    json = {
        'title': 'foo',
        'body':  'bar',
        'userId': 1
    }
    headers     = {'X-Demo': 'true'}
    max_retries = 2

GET /posts/1

PUT /posts/1:
    json = {
        'id':    1,
        'title': 'updated',
        'body':  'Hello Again',
        'userId': 1
    }

DELETE /posts/1

print("All HTTP calls have completed.")
