from aiohttp import web
import ssl

async def handler(request):
    return web.Response(text="Hello world")

app = web.Application()
app.router.add_get('/', handler)

@web.middleware 
async def cors_handler(request, handler):
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response
    
app.middlewares.append(cors_handler)
    

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')
web.run_app(app, ssl_context=ctx, port=443)
print("test")