"""
MIT License

Copyright (c) 2025 Max-Dil

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from lupa import LuaRuntime
import socket as py_socket
import time

lua = LuaRuntime(unpack_returned_tuples=True)

class LuaUDPSocket:
    def __init__(self):
        self.sock = py_socket.socket(py_socket.AF_INET, py_socket.SOCK_DGRAM)

    def setsockname(self, host, port):
        try:
            self.sock.bind((host, int(port)))
            return 1
        except Exception as e:
            print(f"Bind error: {e}")
            return 0

    def settimeout(self, timeout):
        try:
            self.sock.settimeout(float(timeout))
            return 1
        except Exception as e:
            print(f"Settimeout error: {e}")
            return 0

    def receivefrom(self):
        try:
            data, (ip, port) = self.sock.recvfrom(1024)
            return data, ip, port
        except py_socket.timeout:
            return None, "timeout", 0
        except py_socket.error as e:
            if e.errno == 10035:
                return None, "wouldblock", 0
            print(f"Receivefrom error: {e}")
            return None, str(e), 0
        except Exception as e:
            print(f"Receivefrom error: {e}")
            return None, str(e), 0

    def sendto(self, message, ip, port):
        try:
            if isinstance(message, bytes):
                pass
            elif isinstance(message, str):
                message = message.encode('utf-8')
            elif hasattr(message, '__bytes__'):
                message = bytes(message)
            else:
                try:
                    message = str(message).encode('utf-8')
                except:
                    message = repr(message).encode('utf-8')

            self.sock.sendto(message, (ip, int(port)))
            return 1
        except Exception as e:
            print(f"Sendto error: {e}")
            return 0

    def close(self):
        try:
            self.sock.close()
            return 1
        except Exception as e:
            print(f"Close error: {e}")
            return 0

lua_socket_module_server = lua.execute("""
    return {
        udp = nil,
        gettime = nil,
        sleep = nil,
        VERSION = "luasocket stimor in luna"
    }
""")
lua_socket_module_server.udp = lambda: LuaUDPSocket()
lua_socket_module_server.sleep = lambda seconds: time.sleep(float(seconds))
lua_socket_module_server.gettime = lambda: time.time()
lua.globals().socket = lua_socket_module_server

lua.execute("""
package.preload['socket'] = function()
    return _G['socket']
end
""")

lua.execute("""         
success, luna = pcall(require, 'luna.init')
_G.luna = luna

success, lunac = pcall(require, 'lunac.init')
_G.lunac = lunac
""")

# Luna
class Luna_router:
    def __init__(self, router):
        self.__router = router

    def new(self, config_dict):
        config_table = lua.table_from(config_dict)
        return self.__router.new(self.__router, config_table)

    def remove(self, req_data):
        if isinstance(req_data, str):
            self.__router.remove(self.__router, req_data)
        else:
            self.__router.remove(self.__router, req_data)

    @property
    def prefix(self):
        return self.__router.prefix

    @prefix.setter
    def prefix(self, value):
        self.__router.prefix = value

    @property
    def no_errors(self):
        return self.__router.no_errors

    @no_errors.setter
    def no_errors(self, value):
        self.__router.no_errors = value

    @property
    def error_handler(self):
        return self.__router.error_handler

    @error_handler.setter
    def error_handler(self, func):
        self.__router.error_handler = func

    @property
    def requests(self):
        return self.__router.requests

    @property
    def app(self):
        return Luna_app(self.__router.app)

class Luna_app:
    def __init__(self, app):
        self.__app = app

    def new_router(self, config_dict):
        config_table = lua.table_from(config_dict)
        router = self.__app.new_router(self.__app, config_table)
        return Luna_router(router)
    
    def remove_router(self, router_data):
        if isinstance(router_data, str):
            self.__app.remove_router(self.__app, router_data)
        else:
            router_table = lua.table_from(router_data._Luna_router__router)
            self.__app.remove_router(self.__app, router_table)

    @property
    def max_ip_connected(self):
        return self.__app.max_ip_connected

    @max_ip_connected.setter
    def max_ip_connected(self, value):
        self.__app.max_ip_connected = value

    @property
    def name(self):
        return self.__app.name

    @name.setter
    def name(self, value):
        self.__app.name = value

    @property
    def error_handler(self):
        return self.__app.error_handler

    @error_handler.setter
    def error_handler(self, func):
        self.__app.error_handler = func

    @property
    def no_errors(self):
        return self.__app.no_errors

    @no_errors.setter
    def no_errors(self, value):
        self.__app.no_errors = value

    @property
    def host(self):
        return self.__app.host

    @host.setter
    def host(self, value):
        self.__app.host = value

    @property
    def port(self):
        return self.__app.port

    @port.setter
    def port(self, value):
        self.__app.port = value

    @property
    def new_client(self):
        return self.__app.new_client

    @new_client.setter
    def new_client(self, func):
        self.__app.new_client = func

    @property
    def close_client(self):
        return self.__app.close_client

    @close_client.setter
    def close_client(self, func):
        self.__app.close_client = func

    @property
    def request_listener(self):
        return self.__app.request_listener

    @request_listener.setter
    def request_listener(self, func):
        self.__app.request_listener = func

    @property
    def clients(self):
        return self.__app.clients

    @property
    def ip_counts(self):
        return self.__app.ip_counts

    @property
    def routers(self):
        return self.__app.routers

    @property
    def running_funs(self):
        return self.__app.running_funs

    def get_clients(self):
        clients = self.__app.get_clients()
        return [{k: v for k, v in client.items()} for client in clients]

    @property
    def debug(self):
        return self.__app.debug

    @debug.setter
    def debug(self, value):
        self.__app.debug = value

    def set_max_message_size(self, new_max_messages_size):
        self.__app.set_max_message_size(new_max_messages_size)

    def set_max_retries(self, new_max_retries):
        self.__app.set_max_retries(new_max_retries)

    def set_message_timeout(self, new_message_timeout):
        self.__app.set_message_timeout(new_message_timeout)

    @property
    def server_private(self):
        return self.__app.server_private

    @property
    def server_public(self):
        return self.__app.server_public

    @property
    def disconnect_time(self):
        return self.__app.disconnect_time

    @disconnect_time.setter
    def disconnect_time(self, value):
        self.__app.disconnect_time = value

    def set_disconnect_time(self, new_time):
        self.__app.set_disconnect_time(new_time)

class Luna:
    def __init__(self):
        self.__luna = lua.globals().luna

    def new_app(self, config_dict):
        config_table = lua.table_from(config_dict)
        app = self.__luna.new_app(config_table)
        return Luna_app(app)

    def remove_app(self, app_data):
        if isinstance(app_data, str):
            self.__luna.remove_app(app_data)
        else:
            self.__luna.remove_app(app_data._Luna_app__app)

    def update(self, dt):
        self.__luna.update(dt)

# Lunac
class Lunac_app:
    def __init__(self, app):
        self.__app = app
    
    @property
    def name(self):
        return self.__app.name
    
    @name.setter
    def name(self, value):
        self.__app.name = value

    @property
    def host(self):
        return self.__app.host
    
    @host.setter
    def host(self, value):
        self.__app.host = value

    @property
    def port(self):
        return self.__app.port
    
    @port.setter
    def port(self, value):
        self.__app.port = value

    @property
    def no_errors(self):
        return self.__app.no_errors
    
    @no_errors.setter
    def no_errors(self, value):
        self.__app.no_errors = value

    @property
    def error_handler(self):
        return self.__app.error_handler
    
    @error_handler.setter
    def error_handler(self, func):
        self.__app.error_handler = func

    @property
    def listener(self):
        return self.__app.listener
    
    @listener.setter
    def listener(self, func):
        self.__app.listener = func

    @property
    def connected(self):
        return self.__app.connected

    @property
    def client(self):
        return self.__app.client
    
    @property
    def server(self):
        return self.__app.server
    
    @server.setter
    def server(self, value):
        self.__app.server = value

    @property
    def reconnect_time(self):
        return self.__app.reconnect_time
    
    @reconnect_time.setter
    def reconnect_time(self, value):
        self.__app.reconnect_time = value

    @property
    def reconnect_timer(self):
        return self.__app.reconnect_timer

    @property
    def trying_to_reconnect(self):
        return self.__app.trying_to_reconnect

    @property
    def pending_requests(self):
        return self.__app.pending_requests

    @property
    def pending_noawait_requests(self):
        return self.__app.pending_noawait_requests

    @property
    def connect_server(self):
        return self.__app.connect_server
    
    @connect_server.setter
    def connect_server(self, func):
        self.__app.connect_server = func
    
    @property
    def disconnect_server(self):
        return self.__app.disconnect_server
    
    @disconnect_server.setter
    def disconnect_server(self, func):
        self.__app.disconnect_server = func

    @property
    def dt(self):
        return self.__app.dt
    
    @dt.setter
    def dt(self, value):
        self.__app.dt = value

    @property
    def client_token(self):
        return self.__app.client_token
    
    @property
    def client_private(self):
        return self.__app.client_private

    @property
    def client_public(self):
        return self.__app.client_public

    def set_max_message_size(self, new_max_messages_size):
        self.__app.set_max_message_size(new_max_messages_size)

    def set_max_retries(self, new_max_retries):
        self.__app.set_max_retries(new_max_retries)

    def set_message_timeout(self, new_message_timeout):
        self.__app.set_message_timeout(new_message_timeout)

    def fetch(self, path, args=None, timeout=None):
        lua_args = lua.table_from(args) if args is not None else lua.table()
        return self.__app.fetch(self.__app, path, lua_args, timeout)
    
    def noawait_fetch(self, path, callback, args=None):
        lua_args = lua.table_from(args) if args is not None else lua.table()
        self.__app.noawait_fetch(self.__app, path, callback, lua_args)

class Lunac:
    def __init__(self):
        self.__lunac = lua.globals().lunac

    def connect_to_app(self, config_dict):
        config_table = lua.table_from(config_dict)
        app = self.__lunac.connect_to_app(config_table)
        return Lunac_app(app)

    def disconnect_to_app(self, app_data):
        if isinstance(app_data, str):
            self.__lunac.disconnect_to_app(app_data)
        else:
            self.__lunac.disconnect_to_app(app_data._Lunac_app__app)

    def update(self, dt):
        self.__lunac.update(dt)