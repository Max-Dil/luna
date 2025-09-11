import time
from LUNA import Luna, Lunac

luna = Luna()
app = luna.new_app({
    "host": "127.0.0.1",
    "port": 8081,
    "name": "test server",
})

default_router = app.new_router({"prefix": "default"})

def ping_fun(args, client):
    pass

default_router.new({"prefix": "ping", "fun": ping_fun})

main_router = app.new_router({
    "prefix": "api",
})

main_router.new({
    "prefix": "echo",
    "fun": lambda args, client: (
        args.text if hasattr(args, 'text') and args.text is not None 
        else args.get('text', 'no text provided') if hasattr(args, 'get') 
        else 'no text provided'
    )
})

lunac = Lunac()
client = lunac.connect_to_app({
    "host": "127.0.0.1",
    "port": 8081,
    "name": "test server",
    "server": luna._Luna__luna,
})

response = client.fetch("api/echo", {"text": "hello world"})
print("Echo data: ", response)

last_ping_time = time.time()
while True:
    current_time = time.time()
    if current_time - last_ping_time >= 3:
        client.noawait_fetch("default/ping", lambda data, err: (), {})
        last_ping_time = current_time

    luna.update(1/60)
    lunac.update(1/60)
    time.sleep(0.001)