import socket
import threading
from multiprocessing.pool import ThreadPool

from global_utils import *

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


class MiddleNode(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8080):
        super().__init__()
        self.__host = host
        self.__port = port
        self.__stop_requested = threading.Event()
        self.__stopped = threading.Event()
        self.__connection_pool = ThreadPool()
        self.__bufsize = 4096
        self.__group_braid = None
        self.__left_subgroup_braid = None
        self.__right_subgroup_braid = None
        self.__element_x_braid = None
        self.__group_thompson = None
        self.__left_subgroup_thompson = None
        self.__right_subgroup_thompson = None
        self.__element_x_thompson = None
        self.__group_grigorchuk = None
        self.__left_subgroup_grigorchuk = None
        self.__right_subgroup_grigorchuk = None
        self.__element_x_grigorchuk = None
        self.__group_polycyclic = None
        self.__left_subgroup_polycyclic = None
        self.__right_subgroup_polycyclic = None
        self.__element_x_polycyclic = None
        self.__secret_keys_right_subgroup_for_other_nodes = {}
        self.__open_keys_for_other_nodes = {}

    def start(self):
        super().start()
        print('Middle Node running on %(host)s:%(port)s' % {
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
        print('Middle Node is stopped')

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

    def connect_to_server(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))

            sock.sendall(json.dumps({
                "method": "get_groups",
                "params": {}
            }).encode())
            res = recvall(sock)
            print(res)
            if res['status_code'] == 0:
                self.__groups = res['data'][0]
                self.__group_braid = self.__groups[EncryptMethods.BRAID][0]
                self.__left_subgroup_braid = self.__groups[EncryptMethods.BRAID][1]
                self.__right_subgroup_braid = self.__groups[EncryptMethods.BRAID][2]
                self.__element_x_braid = self.__groups[EncryptMethods.BRAID][3]
                self.__group_thompson = self.__groups[EncryptMethods.THOMPSON][0]
                self.__left_subgroup_thompson = self.__groups[EncryptMethods.THOMPSON][1]
                self.__right_subgroup_thompson = self.__groups[EncryptMethods.THOMPSON][2]
                self.__element_x_thompson = self.__groups[EncryptMethods.THOMPSON][3]
                self.__group_grigorchuk = self.__groups[EncryptMethods.GRIGORCHUK][0]
                self.__left_subgroup_grigorchuk = self.__groups[EncryptMethods.GRIGORCHUK][1]
                self.__right_subgroup_grigorchuk = self.__groups[EncryptMethods.GRIGORCHUK][2]
                self.__element_x_grigorchuk = self.__groups[EncryptMethods.GRIGORCHUK][3]
                self.__group_polycyclic = self.__groups[EncryptMethods.POLYCYCLIC][0]
                self.__left_subgroup_polycyclic = self.__groups[EncryptMethods.POLYCYCLIC][1]
                self.__right_subgroup_polycyclic = self.__groups[EncryptMethods.POLYCYCLIC][2]
                self.__element_x_polycyclic = self.__groups[EncryptMethods.POLYCYCLIC][3]

                self.__secret_keys_right_subgroup_for_other_nodes = {
                    EncryptMethods.BRAID: gen_secret_key(self.__right_subgroup_braid, gen_length_braid()),
                    EncryptMethods.THOMPSON: gen_secret_key(self.__right_subgroup_thompson, gen_length_thompson()),
                    EncryptMethods.GRIGORCHUK: gen_secret_key(self.__right_subgroup_grigorchuk,
                                                              gen_length_grigorchuk()),
                    EncryptMethods.POLYCYCLIC: gen_secret_key(self.__right_subgroup_polycyclic,
                                                              gen_length_polycyclic())}

                self.__open_keys_for_other_nodes = {
                    EncryptMethods.BRAID: create_open_key(
                        self.__secret_keys_right_subgroup_for_other_nodes[EncryptMethods.BRAID],
                        self.__element_x_braid),
                    EncryptMethods.THOMPSON: create_open_key(
                        self.__secret_keys_right_subgroup_for_other_nodes[EncryptMethods.THOMPSON],
                        self.__element_x_thompson),
                    EncryptMethods.GRIGORCHUK: create_open_key(
                        self.__secret_keys_right_subgroup_for_other_nodes[EncryptMethods.GRIGORCHUK],
                        self.__element_x_grigorchuk),
                    EncryptMethods.POLYCYCLIC: create_open_key(
                        self.__secret_keys_right_subgroup_for_other_nodes[EncryptMethods.POLYCYCLIC],
                        self.__element_x_polycyclic)}

                sock.sendall(json.dumps({
                    "method": "add_node",
                    "params": {
                        "addr": self.__host,
                        "port": self.__port,
                        "open_keys": self.__open_keys_for_other_nodes
                    }
                }).encode())

                res = recvall(sock)
                print(res)

    @request_method('create')
    def create_request(self, kwargs):
        if ('c1' in kwargs.keys() and
                'conjugate_braid' in kwargs.keys() and
                'algorithm' in kwargs.keys() and
                'encrypted_message' in kwargs.keys()):
            return {
                'response': 'created',
                'hash': 'J978tGYG87g0IUIUT67tr8OYG78tGLIK',
                'conjugate_algorithm': 'braid'
            }
        raise Exception('Incorrect params')
