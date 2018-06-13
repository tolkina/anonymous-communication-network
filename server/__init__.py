from multiprocessing.pool import ThreadPool
import socket
import threading
import json
import server_utils

__requests = {}


def request_method(func_name):
    def request_decorator(func):
        __requests[func_name] = func

    return request_decorator


def run_request_method(name, args):
    if name in __requests.keys():
        try:
            res = __requests[name](*args)
            return json.dumps({
                'status_code': 0,
                'data': res
            })
        except Exception as e:
            return json.dumps({
                'status_code': 1,
                'error_message': repr(e)
            })
    return json.dumps({
        'status_code': 1,
        'error_message': 'Invalid function'
    })


class Server(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8080):
        super().__init__()
        self.__host = host
        self.__port = port
        self.__stop_requested = threading.Event()
        self.__stopped = threading.Event()
        self.__groups = server_utils.get_groups()
        self.__connection_pool = ThreadPool()
        self.__bufsize = 4096
        self.__requests = {}
        self.__nodes_list = []

    def start(self):
        super().start()
        print('Server running on %(host)s:%(port)s' % {
            'host': self.__host,
            'port': self.__port
        })

    def run(self):
        self.__stop_requested.clear()
        self.__stopped.clear()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.__host, self.__port))
            sock.settimeout(3)
            sock.listen()
            while not self.__stop_requested.is_set():
                try:
                    conn, addr = sock.accept()
                    self.__connection_pool.apply_async(self.__connection_handler, (conn,))
                except socket.timeout:
                    pass
        self.__stopped.set()

    def stop(self):
        self.__stop_requested.set()
        self.__stopped.wait()
        print('Server is stopped')

    def __connection_handler(self, conn):
        with conn:
            try:
                while True:
                    if self.__stop_requested.is_set():
                        break
                    data = b''
                    while True:
                        if self.__stop_requested.is_set():
                            break
                        chunk = conn.recv(self.__bufsize)
                        data += chunk
                        if len(chunk) < self.__bufsize:
                            break
                    if len(data) > 0:
                        data = data.decode()
                        decoded_data = json.loads(data)
                        res = run_request_method(decoded_data['method'], (self, decoded_data['params']))
                        conn.sendall(res.encode())
            except Exception as e:
                print(e)

    @request_method('get_groups')
    def get_group_request(self, kwargs):
        return [self.__groups]

    @request_method('add_node')
    def add_to_list_request(self, kwargs):
        if 'addr' in kwargs.keys() and 'port' in kwargs.keys() and 'open_keys' in kwargs.keys():
            for item in self.__nodes_list:
                if (item['addr'] == kwargs['addr'] and
                        item['port'] == kwargs['port'] and
                        item['open_keys'] == kwargs['open_keys']):
                    raise Exception('Node already exists')
            self.__nodes_list.append({
                "addr": kwargs['addr'],
                "port": kwargs['port'],
                "open_keys": kwargs['open_keys']
            })
            return True
        raise Exception('Incorrect request')

    @request_method('get_nodes')
    def get_nodes_request(self, kwargs):
        if len(self.__nodes_list) > 3:
            return self.__nodes_list
        raise Exception('There are less then three nodes')
