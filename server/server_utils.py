import json
import random
import numpy

# from sage.all import *

from global_utils import gen_length_braid


def gen_n_braid():
    return random.randint(6, 8)


def gen_group_braid(n):
    # b = BraidGroup(n)
    b = [i for i in range(1, n + 1)]
    # return [b([i]) for i in range(1, n)]
    return [b[i] for i in range(n)]


def gen_left_subgroup_braid(group_braid, n):
    # return [group_braid([i]) for i in range(1, n // 2 + 1)]
    return [group_braid[i] for i in range(1, n // 2 + 1)]


def gen_right_subgroup_braid(group_braid, n):
    # return [group_braid([i]) for i in range(n // 2 + 2, n)]
    return [group_braid[i] for i in range(n // 2 + 2, n)]


def gen_element_x_braid(group_braid):
    length = gen_length_braid()
    return [random.choice(group_braid) for _ in range(length)]


def gen_n_thompson():
    return random.randint(6, 8)


def gen_group_thompson(n_thompson):
    return gen_group_braid(n_thompson)


def gen_left_subgroup_thompson(group_thompson, n_thompson):
    return gen_left_subgroup_braid(group_thompson, n_thompson)


def gen_right_subgroup_thompson(group_thompson, n_thompson):
    return gen_right_subgroup_braid(group_thompson, n_thompson)


def gen_element_x_thompson(group_thompson):
    return gen_element_x_braid(group_thompson)


def gen_n_grigorchuk():
    return random.randint(6, 8)


def gen_group_grigorchuk(n_grigorchuk):
    return gen_group_braid(n_grigorchuk)


def gen_left_subgroup_grigorchuk(group_grigorchuk, n_grigorchuk):
    return gen_left_subgroup_braid(group_grigorchuk, n_grigorchuk)


def gen_right_subgroup_grigorchuk(group_grigorchuk, n_grigorchuk):
    return gen_right_subgroup_braid(group_grigorchuk, n_grigorchuk)


def gen_element_x_grigorchuk(group_grigorchuk):
    return gen_element_x_braid(group_grigorchuk)


def gen_n_polycyclic():
    return random.randint(6, 8)


def gen_group_polycyclic(n_polycyclic):
    return gen_group_braid(n_polycyclic)


def gen_left_subgroup_polycyclic(group_polycyclic, n_polycyclic):
    return gen_left_subgroup_braid(group_polycyclic, n_polycyclic)


def gen_right_subgroup_polycyclic(group_polycyclic, n_polycyclic):
    return gen_right_subgroup_braid(group_polycyclic, n_polycyclic)


def gen_element_x_polycyclic(group_polycyclic):
    return gen_element_x_braid(group_polycyclic)


def get_groups():
    n_braid = gen_n_braid()
    group_braid = gen_group_braid(n_braid)
    left_subgroup_braid = gen_left_subgroup_braid(group_braid, n_braid)
    right_subgroup_braid = gen_right_subgroup_braid(group_braid, n_braid)
    element_x_braid = gen_element_x_braid(group_braid)

    n_thompson = gen_n_braid()
    group_thompson = gen_group_thompson(n_thompson)
    left_subgroup_thompson = gen_left_subgroup_thompson(group_thompson, n_thompson)
    right_subgroup_thompson = gen_right_subgroup_thompson(group_thompson, n_thompson)
    element_x_thompson = gen_element_x_thompson(group_thompson)

    n_grigorchuk = gen_n_braid()
    group_grigorchuk = gen_group_grigorchuk(n_grigorchuk)
    left_subgroup_grigorchuk = gen_left_subgroup_grigorchuk(group_grigorchuk, n_grigorchuk)
    right_subgroup_grigorchuk = gen_right_subgroup_grigorchuk(group_grigorchuk, n_grigorchuk)
    element_x_grigorchuk = gen_element_x_grigorchuk(group_grigorchuk)

    n_polycyclic = gen_n_braid()
    group_polycyclic = gen_group_polycyclic(n_polycyclic)
    left_subgroup_polycyclic = gen_left_subgroup_polycyclic(group_polycyclic, n_polycyclic)
    right_subgroup_polycyclic = gen_right_subgroup_polycyclic(group_polycyclic, n_polycyclic)
    element_x_polycyclic = gen_element_x_polycyclic(group_polycyclic)

    return {"Braid": [group_braid, left_subgroup_braid, right_subgroup_braid, element_x_braid],
            "Thompson": [group_thompson, left_subgroup_thompson, right_subgroup_thompson, element_x_thompson],
            "Grigorchuk": [group_grigorchuk, left_subgroup_grigorchuk, right_subgroup_grigorchuk,
                           element_x_grigorchuk],
            "Polycyclic": [group_polycyclic, left_subgroup_polycyclic, right_subgroup_polycyclic,
                           element_x_polycyclic]}


def recvall(sock):
    data = b''
    while True:
        t = sock.recv(4096)
        data += t
        if len(t) < 4096:
            break
    return json.loads(data.decode())
