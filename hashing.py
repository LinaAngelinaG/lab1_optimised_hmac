import io
import struct

SHA1_BLOCK_SIZE = 64
UNPROC = b''
HS = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)
OPAD = bytearray(b'\x5c') * 64
IPAD = bytearray(b'\x36') * 64
d_len = 20
b_len = 64


def new(key, message):
    if len(key) < SHA1_BLOCK_SIZE:
        key = key + bytearray(SHA1_BLOCK_SIZE - len(key))
    upd_mes = bytes(a ^ b for (a, b) in zip(key, IPAD)) + message
    hashed = sha1(upd_mes)
    upd_mes = bytes(a ^ b for (a, b) in zip(key, OPAD)) + bytes.fromhex(hashed)
    return bytes.fromhex(sha1(upd_mes))


def new_f_hash(key):
    if len(key) < SHA1_BLOCK_SIZE:
        zero_padding = bytearray(SHA1_BLOCK_SIZE - len(key))
        key = key + zero_padding
    key_xor_ipad = bytes(a ^ b for (a, b) in zip(key, IPAD))
    h_1 = sha1_1_hash(key_xor_ipad)
    key_xor_opad = bytes(a ^ b for (a, b) in zip(key, OPAD))
    h_2 = sha1_1_hash(key_xor_opad)
    return (h_1, h_2)


def new_trunc(message, first_hash, second_hash):
    hashed = sha1_to_init(message, first_hash)
    result_hash = sha1_to_init(bytes.fromhex(hashed), second_hash)
    return bytes.fromhex(result_hash)


def do_abcde(h0, h1, h2, h3, h4, a, b, c, d, e):
    div = 0xffffffff
    return (h0 + a) & div, (h1 + b) & div, (h2 + c) & div, (h3 + d) & div, (h4 + e) & div


def rotate_leftside(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def abcde_func_part(bite, h0, h1, h2, h3, h4):
    w = [0] * 80
    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(16):
        w[i] = struct.unpack(b'>I', bite[i * 4:i * 4 + 4])[0]
    for i in range(16, 80):
        w[i] = rotate_leftside(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    for i in range(80):
        if i < 20:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif i < 40 or i >= 60:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
            if i >= 60:
                k = 0xCA62C1D6
        elif i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC

        a, b, c, d, e = ((rotate_leftside(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, rotate_leftside(b, 30), c, d)
    return do_abcde(h0, h1, h2, h3, h4, a, b, c, d, e)


def sha1_1_hash(arg):
    if isinstance(arg, (bytes, bytearray)):
        arg = io.BytesIO(arg)
    bite = UNPROC + arg.read(64 - len(UNPROC))
    return abcde_func_part(bite, *HS)


def sha1_to_init(arg, init_hash):
    unp = UNPROC
    b_len = 0

    if isinstance(arg, (bytes, bytearray)):
        arg = io.BytesIO(arg)
    bite = unp + arg.read(64 - len(unp))
    hs = init_hash
    while len(bite) == 64:
        hs = abcde_func_part(bite, *hs)
        b_len += 64
        bite = arg.read(64)

    message = bite
    message_byte_length = b_len + len(message) + 64
    message += b'\x80'
    message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)
    h = abcde_func_part(message[:64], *hs)
    if len(message) == 64:
        return  '%08x%08x%08x%08x%08x' %  h
    return '%08x%08x%08x%08x%08x' % abcde_func_part(message[64:], *h)


def sha1(arg):
    if isinstance(arg, (bytes, bytearray)):
        arg = io.BytesIO(arg)
    bite = UNPROC + arg.read(64 - len(UNPROC))
    hs = HS
    b_len = 0

    while len(bite) == 64:
        hs = abcde_func_part(bite, *hs)
        b_len += 64
        bite = arg.read(64)

    message = bite
    b_len += len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (b_len + 1) % 64) % 64)
    message_bit_length = b_len * 8
    message += struct.pack(b'>Q', message_bit_length)
    h = abcde_func_part(message[:64], *hs)
    if len(message) == 64:
        return h
    return '%08x%08x%08x%08x%08x' % abcde_func_part(message[64:], *h)
