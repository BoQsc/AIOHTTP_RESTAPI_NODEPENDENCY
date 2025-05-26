from aiohttp import web
import ssl
import json

async def handler(request):
    return web.Response(text="Hello world")

async def echo_handler(request):
    """Handle POST requests to /echo endpoint"""
    try:
        data = await request.json()
        return web.json_response({
            "received": data,
            "method": request.method,
            "path": request.path
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

@web.middleware 
async def cors_handler(request, handler):
    # Handle preflight OPTIONS requests
    if request.method == 'OPTIONS':
        response = web.Response()
    else:
        try:
            response = await handler(request)
        except web.HTTPException as ex:
            # Handle HTTP exceptions (like 404) and still add CORS headers
            response = web.Response(
                text=ex.text or ex.reason,
                status=ex.status
            )
    
    # Add CORS headers to all responses
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    
    return response

# Create app and add middleware FIRST
app = web.Application()
app.middlewares.append(cors_handler)

# Add routes AFTER middleware
app.router.add_get('/', handler)
app.router.add_post('/echo', echo_handler)

# Optional: Add a catch-all OPTIONS handler for any route
async def options_handler(request):
    return web.Response()

app.router.add_route('OPTIONS', '/{path:.*}', options_handler)

# SSL setup
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')

if __name__ == '__main__':
    web.run_app(app, ssl_context=ctx, port=443)