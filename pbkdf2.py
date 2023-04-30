import math
import hmac
import hashing

LENGTH = 20


def gen_opt(p, s, c, i):
    result = []
    u_i = []
    _h_1, _h_2 = hashing.new_f_hash(p)
    for k in range(c):
        if k == 0:
            u_i = hashing.new_trunc(s + bytearray([i]), _h_1, _h_2)
        else:
            u_i = hashing.new_trunc(u_i, _h_1, _h_2)
        result += u_i

    return result


def gen(p, s, c, i):
    result = []
    u_i = []
    for k in range(c):
        if k == 0:
            u_i = hmac.new(p, s + bytearray([i]), "sha1").digest()
        else:
            u_i = hmac.new(p, u_i, "sha1").digest()
        result += u_i

    return result


def gen_passw(p, s, c, dk_len):
    l = math.ceil(dk_len / LENGTH)
    result = []
    for j in range(l):
        t_j = gen(p, s, c, j)
        result += t_j
    return result[:dk_len]


def gen_passw_opt(p, s, c, dk_len):
    l = math.ceil(dk_len / LENGTH)
    result = []
    for j in range(l):
        t_j = gen_opt(p, s, c, j)
        result += t_j
    return result[:dk_len]


