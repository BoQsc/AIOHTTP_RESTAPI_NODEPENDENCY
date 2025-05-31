from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# In-memory storage for posts
posts = {}
next_id = 1

@app.route('/posts', methods=['POST'])
def create_post():
    global next_id
    data = request.get_json()
    post = {
        'id': next_id,
        'title': data.get('title', ''),
        'body': data.get('body', ''),
        'userId': data.get('userId', 1)
    }
    posts[next_id] = post
    next_id += 1
    
    print(f"Created post: {post}")
    return jsonify(post), 201

@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    if post_id in posts:
        print(f"Retrieved post {post_id}: {posts[post_id]}")
        return jsonify(posts[post_id])
    else:
        return jsonify({'error': 'Post not found'}), 404

@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    if post_id in posts:
        data = request.get_json()
        posts[post_id].update(data)
        print(f"Updated post {post_id}: {posts[post_id]}")
        return jsonify(posts[post_id])
    else:
        return jsonify({'error': 'Post not found'}), 404

@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if post_id in posts:
        deleted_post = posts.pop(post_id)
        print(f"Deleted post {post_id}: {deleted_post}")
        return '', 204
    else:
        return jsonify({'error': 'Post not found'}), 404

@app.route('/posts', methods=['GET'])
def list_posts():
    return jsonify(list(posts.values()))

if __name__ == '__main__':
    print("Starting test server on http://localhost:8000")
    print("Available endpoints:")
    print("  POST /posts - Create a post")
    print("  GET /posts/<id> - Get a post")
    print("  PUT /posts/<id> - Update a post")
    print("  DELETE /posts/<id> - Delete a post")
    print("  GET /posts - List all posts")
    app.run(host='localhost', port=8000, debug=True)