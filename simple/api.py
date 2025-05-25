from aiohttp import web
import ssl

async def handler(request):
    return web.Response(text="Hello world")

app = web.Application()
app.router.add_get('/', handler)

ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain('cert.pem', 'key.pem')
web.run_app(app, ssl_context=ctx, port=443)