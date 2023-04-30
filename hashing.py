import io
import struct
import hashing
from __future__ import print_function


SHA1_BLOCK_SIZE = 64
SHA1_DLOCK_BITS = SHA1_BLOCK_SIZE * 8
OPAD = bytearray(b'\x5c')*64
IPAD = bytearray(b'\x36')*64


def new(key, message):
    if len(key) < SHA1_BLOCK_SIZE:
        zero_padding = bytearray(SHA1_BLOCK_SIZE - len(key))
        key = key + zero_padding
    key_xor_ipad = bytes(a ^ b for (a, b) in zip(key, IPAD))
    key_xor_ipad = key_xor_ipad + message
    hashed = sha1.sha1(key_xor_ipad)
    key_xor_opad = bytes(a ^ b for (a, b) in zip(key, OPAD))
    key_xor_opad = key_xor_opad + bytes.fromhex(hashed)
    result_hash = sha1.sha1(key_xor_opad)
    return bytes.fromhex(result_hash)


def new_f_hash(key):
    if len(key) < SHA1_BLOCK_SIZE:
        zero_padding = bytearray(SHA1_BLOCK_SIZE - len(key))
        key = key + zero_padding
    key_xor_ipad = bytes(a ^ b for (a, b) in zip(key, IPAD))
    _h_1 = hashing.sha1_1_hash(key_xor_ipad)
    key_xor_opad = bytes(a ^ b for (a, b) in zip(key, OPAD))
    _h_2 = hashing.sha1_1_hash(key_xor_opad)
    return (_h_1, _h_2)


def new_trunc(message, first_hash, second_hash):
    hashed = hashing.sha1_to_init(message, first_hash)
    result_hash = hashing.sha1_to_init(bytes.fromhex(hashed), second_hash)
    return bytes.fromhex(result_hash)


class Sha1Hash(object):
    digest_len = 20
    block_len = 64

    def __init__(self):
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )
        self._unprocessed = b''
        self._message_byte_length = 0

    def update(self, arg):
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))
        while len(chunk) == 64:
            self._h = process_part(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def update_trunc(self, arg, init_hash):

        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))
        self._h = init_hash
        while len(chunk) == 64:
            self._h = process_part(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def get_first_hash(self, arg):
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        return process_part(chunk, *self._h)

    def digest(self):
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)
        message += b'\x80'
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)
        h = process_part(message[:64], *self._h)
        if len(message) == 64:
            return h
        return process_part(message[64:], *h)

    def hexdigest_trunc(self):
        return '%08x%08x%08x%08x%08x' % self._produce_digest_trunc()

    def _produce_digest_trunc(self):
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message) + 64
        message += b'\x80'
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)
        h = process_part(message[:64], *self._h)
        if len(message) == 64:
            return h
        return process_part(message[64:], *h)


def sha1(data):
    return Sha1Hash().update(data).hexdigest()


def sha1_1_hash(data):
    return Sha1Hash().get_first_hash(data)


def sha1_to_init(data, init_hash):
    return Sha1Hash().update_trunc(data, init_hash).hexdigest_trunc()


if __name__ == '__main__':
    import argparse
    import sys
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument('input', nargs='*',
                        help='input file or message to hash')
    args = parser.parse_args()

    data = None
    if len(args.input) == 0:
        try:
            data = sys.stdin.detach()

        except AttributeError:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            data = sys.stdin
        print('sha1-digest:', sha1(data))

    else:
        for argument in args.input:
            if (os.path.isfile(argument)):
                data = open(argument, 'rb')
                print('sha1-digest:', sha1(data))
            else:
                print("Error, could not find " + argument + " file.")


def rotate_leftside(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def process_part(chunk, h0, h1, h2, h3, h4):
    assert len(chunk) == 64
    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]
    for i in range(16, 80):
        w[i] = rotate_leftside(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((rotate_leftside(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, rotate_leftside(b, 30), c, d)

    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4
