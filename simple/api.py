from aiohttp import web
import ssl

async def handler(request):
    return web.Response(text="Hello world")

app = web.Application()
app.router.add_get('/', handler)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('boqsc.eu_fullchain.pem')
web.run_app(app, ssl_context=ctx, port=443)