import json
import random
import socket

import numpy


def recvall(sock):
    data = b''
    while True:
        t = sock.recv(4096)
        data += t
        if len(t) < 4096:
            break
    return json.loads(data.decode())


class EncryptMethods:
    BRAID = "Braid"
    THOMPSON = "Thompson"
    GRIGORCHUK = "Grigorchuk"
    POLYCYCLIC = "Polycyclic"


def gen_length_braid():
    return random.choice(range(256, 322, 2))


def gen_length_thompson():
    return random.choice(range(256, 322, 2))


def gen_length_grigorchuk():
    return random.choice(range(256, 322, 2))


def gen_length_polycyclic():
    return random.choice(range(256, 322, 2))


def gen_secret_key(right_subgroup, length):
    return numpy.prod([random.choice(right_subgroup) for _ in range(length)])


def pow_a(w, a):
    # return a ** -1 * w * a
    return 5


def create_open_key(secret_key, element_x):
    return pow_a(element_x, secret_key)


def gen_chain(nodes, secret_keys_right_subgroup, element_x_braid, left_subgroup_braid, element_x_thompson,
              left_subgroup_thompson, element_x_grigorchuk, left_subgroup_grigorchuk, element_x_polycyclic,
              left_subgroup_polycyclic):
    if len(nodes) < 4:
        return []
    three_nodes = [random.choice(nodes) for _ in range(3)]
    three_methods = [EncryptMethods.THOMPSON, EncryptMethods.GRIGORCHUK, EncryptMethods.POLYCYCLIC]
    random.shuffle(three_methods)
    f = []
    my_open_key_thompson = create_open_key(secret_keys_right_subgroup[EncryptMethods.THOMPSON], element_x_thompson)
    my_secret_key_thompson = gen_secret_key(left_subgroup_thompson, gen_length_braid())
    my_open_key_grigorchuk = create_open_key(secret_keys_right_subgroup[EncryptMethods.GRIGORCHUK],
                                             element_x_grigorchuk)
    my_secret_key_grigorchuk = gen_secret_key(left_subgroup_grigorchuk, gen_length_braid())
    my_open_key_polycyclic = create_open_key(secret_keys_right_subgroup[EncryptMethods.POLYCYCLIC],
                                             element_x_polycyclic)
    my_secret_key_polycyclic = gen_secret_key(left_subgroup_polycyclic, gen_length_braid())

    my_method_keys = {
        "Thompson": [my_open_key_thompson, my_secret_key_thompson],
        "Grigorchuk": [my_open_key_grigorchuk, my_secret_key_grigorchuk],
        "Polycyclic": [my_open_key_polycyclic, my_secret_key_polycyclic]}

    for i in range(len(three_nodes)):
        my_open_key_braid = create_open_key(secret_keys_right_subgroup[EncryptMethods.BRAID], element_x_braid)
        my_secret_key_braid = gen_secret_key(left_subgroup_braid, gen_length_braid())
        f.append({'method': three_methods[i],
                  'node': {'addr': three_nodes[i]['addr'], 'port': three_nodes[i]['port'],
                           'open_key_method': three_nodes[i]['open_keys'][three_methods[i]],
                           'open_key_braid': three_nodes[i]['open_keys'][EncryptMethods.BRAID]},
                  'me': {"open_key_braid": my_open_key_braid, "secret_key_braid": my_secret_key_braid,
                         "open_key_method": my_method_keys[three_methods[i]][0],
                         "secret_key_method": my_method_keys[three_methods[i]][1]}})
    return f


def send_request(host, port, method, params):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(json.dumps({
            "method": method,
            "params": params
        }).encode())
        res = recvall(sock)
        return res
