import argparse
from Crypto.Cipher import DES3
import hashlib
import string
import random
import hashing

N_r = "8a944e963630cace46d87baa6f995bd253eb9a80cff8f0f9a1bddd4d1732c37c"
N_i = "0f20628aa4efd7b92ca9554380a712a186cf99feddf36a9a3003a5a68ad6f749"
Ci = "c1ae2e732461ddcc"
Cr = "f82a8c311e1a3eb7"
SAi = "00000001000000010000002c000100010000002400010000800b0001800c0e1080010007800e0080800200028003000180040002"
IDii_b = "01110000c0a80c02"
IDii = "0800000c01110000c0a80c02"
PLACE = "*"

MAX_G_SIZE = 128
MIN_G_SIZE = 64


def get_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length)).encode().hex()


def get_hash_id(mode):
    return '1' if mode == 'md5' else '2'


def get_enc_if(mode):
    if mode == '3des':
        return '5'
    elif mode == 'aes128':
        return '7'
    elif mode == 'aes192':
        return '8'
    else:
        return '9'


def get_key_size(mode):
    if mode == '3des':
        return 16
    elif mode == 'aes128':
        return 16
    elif mode == 'aes192':
        return 24
    else:
        return 32


def get_block_size(mode):
    if mode == '3des':
        return 8
    else:
        return 16


# HASH_id*ALG_id*Ni*Nr*g_x*g_y*g_xy*Ci*Cr*SAi*E_k
def gen_output_file(passw, hash_mode, enc_mode, g_x, g_y, g_xy, e_k):
    with open(passw + "_" + hash_mode + "_" + enc_mode + ".txt", "w") as file:
        file.write(get_hash_id(hash_mode) + PLACE +
                   get_enc_if(enc_mode) + PLACE +
                   N_i + PLACE +
                   N_r + PLACE +
                   g_x + PLACE +
                   g_y + PLACE +
                   g_xy + PLACE +
                   Ci + PLACE +
                   Cr + PLACE +
                   SAi + PLACE +
                   e_k)


def prf_init(password):
    h_1, h_2 = hashing.new_f_hash(bytes.fromhex(password))
    return (h_1, h_2)


def prf_trunc(nonce, hash_1, hash_2):
    return hashing.new_trunc(bytes.fromhex(nonce), hash_1, hash_2)


def prf(password, nonce):
    h_1, h_2 = hashing.new_f_hash(bytes.fromhex(password))
    return hashing.new_trunc(bytes.fromhex(nonce), h_1, h_2)


def get_iv_for_mode(encoding_algo, g_x_conc_g_y):
    return hashlib.sha1(bytes.fromhex(g_x_conc_g_y)).digest()[:get_block_size(encoding_algo)]


def encoding(encoding_algo, key, data, iv):
    if len(bytes.fromhex(data)) % 16 != 0:
        data = data + bytes([0x00 for i in range(len(bytes.fromhex(data)) % 16)]).hex()
    if encoding_algo == '3des':
        cipher = DES3.new(key, DES3.MODE_CBC, IV=iv)
        return cipher.encrypt(bytes.fromhex(data)).hex()


def key_gen(s_key_id, nonce, opt):
    if opt:
        hash_1, hash_2 = prf_init(s_key_id)
        s_key_id_d = prf_trunc(nonce + '00', hash_1, hash_2).hex()
        s_key_id_a = prf_trunc(s_key_id_d + nonce + '01', hash_1, hash_2).hex()
        s_key_id_e = prf_trunc(s_key_id_a + nonce + '02', hash_1, hash_2)
    else:
        s_key_id_d = prf(s_key_id, nonce + '00').hex()
        s_key_id_a = prf(s_key_id, s_key_id_d + nonce + '01').hex()
        s_key_id_e = prf(s_key_id, s_key_id_a + nonce + '02')

    if len(s_key_id_e) < get_key_size('3des'):
        k_1 = prf(s_key_id_e.hex(), '00')
        k_2 = prf(s_key_id_e.hex(), k_1.hex())
        k = k_1 + k_2
        return k[:get_key_size('3des')]
    elif len(s_key_id_e) > get_key_size('3des'):
        return s_key_id_e[:get_key_size('3des')]
    return s_key_id_e


def process(args):
    G_x = "a4ba2df0fc47dbf5d57883140a8289c15a7423bdf0c6f2e2d039a123719d6957def99b1b4372cdebdc055ad164ea21848885191a8b59ac46cd382294e598fae71013869659835db2ae69f616689c751ce03d3e7c0ea1c8d99daaacf652d5ed08948387aa3d39695be4914bdf425de692060c9fb35ea1e387a9b54dcc02ac0af5" #get_random_string(MIN_G_SIZE)
    G_y = "538d6bde8d6d566bc03445eec118a7d18fe58d4d4f766d6157a295ce5474f1fdacc00c073412da2b5af93ada36e696daa32c62a3ab9548cf0c67f2d387f473ae79f9465dbb3c7703b265c6b3bf5ca6182b1dd35107e940efdddea7011a3bcc0ef4b31ef06125cdeda02a96157a7232153405b8918f1be0c18fb0cb3f338ce564" #get_random_string(MIN_G_SIZE)
    G_xy = "5795c69c8fe8802204fcd52077f899be0fa439579e39b773084508c25ae68a95b2a2dcbac4fdd293dd9cb9dca684c6902c3b9a0e47d4791dc9dc408be0e58564121a1a44388e2885b1940865740868ad4a934ef95a144c47e4cb061c907bfbf8a1611dca168bfb4e74fd65a61545612be0f2d93f0baa42272822893056e99b96" #get_random_string(MAX_G_SIZE)

    s_key_id = prf(args.password.encode().hex(), N_i + N_r).hex()
    hash_i = prf(s_key_id, G_x + G_y + Ci + Cr + SAi + IDii_b).hex()
    s_key_id_e = key_gen(s_key_id, G_xy + Ci + Cr, args.opt)

    iv = get_iv_for_mode('3des', G_x + G_y)
    payload_hash_i = [0x00, 0x00, 0x00, int((len(hash_i)/2) + 4)]
    e_k = encoding('3des', s_key_id_e, IDii + bytes(payload_hash_i).hex() + hash_i, iv)
    gen_output_file(args.password, 'sha1', '3des', G_x, G_y, G_xy, e_k)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-p',
                        '--password',
                        action='store',
                        type=str,
                        required=True,
                        help='set password value')
    parser.add_argument('-o',
                        '--opt',
                        type=bool,
                        default=False,
                        help='set version optimised/non')
    process(parser.parse_args())

