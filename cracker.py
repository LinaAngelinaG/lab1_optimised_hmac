import argparse
import hashlib
import pathlib
import string
import time
from typing import Tuple, Union, Dict, List

import generator
from Crypto.Cipher import DES3

LETTER2ASCII_LETTERS: Dict[str, List[str]] = {
    'a': list(string.ascii_letters) + list(string.digits + '!'),
    'l': list(string.ascii_lowercase),
    'u': list(string.ascii_uppercase),
    'd': list(string.digits + '!'),
}


def gain_params_from_file(filename: str) -> Tuple[str, str, str, Union[int, bytes], str]:
    with open(filename, "r") as f:
        text = f.read()

    bites = text.split('*')
    if len(bites) == 11:

        N_i, N_r, G_x, G_y, G_xy, Ci, Cr, SAi, E_k = bites[2:11]

        N_3 = G_xy + Ci + Cr
        N_2 = G_x + G_y + Ci + Cr + SAi
        N_1 = N_i + N_r

        iv = hashlib.sha1(bytes.fromhex(G_x + G_y)).digest()[:8]

        return N_1, N_2, N_3, iv, E_k
    else:
        raise ValueError(f"not enough values - {len(bites)}, need - 11")


def is_mask_valid(mask: str) -> bool:
    for mask_parameter in mask:
        if mask_parameter not in ['a', 'd', 'l', 'u']:
            return False
    return True


def gen_passwords(mask: str, dict_file: str) -> list:
    list_passw = [LETTER2ASCII_LETTERS[letter] for letter in mask]
    with open(dict_file, "r") as f:
        res = f.readlines()
    passws = [word[:-1] if word[-1] == '\n' else word for word in res]

    return [passws] + list_passw


def get_ords_bases(passwords: List[str]) -> List[int]:
    ords_bases = []

    for i, p in enumerate(passwords):
        ords_bases.append(len(p) if i == 0 else ords_bases[i - 1] * len(p))
    return ords_bases


def get_passwords_count(passwords: List[str]) -> int:
    passwords_count = 1
    for custom_alphabet in passwords:
        passwords_count *= len(custom_alphabet)
    return passwords_count


def process(args):
    if not is_mask_valid(args.mask):
        ValueError(f"Invalid mask - {args.mask}")

    passwords = gen_passwords(args.mask, args.dict)
    nonce_1, nonce_2_prt, nonce_3, iv, e_k = gain_params_from_file(args.file)
    brute(passwords, nonce_1, nonce_2_prt, nonce_3, e_k, iv, args.opt)


def decrypt(e_k, iv, skey_id_e):
    text = DES3.new(skey_id_e, DES3.MODE_CBC, IV=iv).decrypt(bytes.fromhex(e_k)).hex()
    # IDi_len = 24,HASH_len = 4, sep = 40: (IDi_len + HASH_len  * 2):(IDi_len + HASH_len * 2 + sep)
    return text[:24], text[32:72]


def brute(passwords, nonce_1, nonce_2_prt, nonce_3, e_k, iv, opt):
    bases = get_ords_bases(passwords=passwords)
    num_passwords = get_passwords_count(passwords=passwords)

    counter = 0
    start = time.time()
    for password in range(num_passwords):
        p_word = ''
        for i in range(len(bases)):
            counter += 1
            alp_m = passwords[i]
            alp_m_len = len(alp_m)
            p_word += (
                alp_m[password % bases[i]] if i == 0 else alp_m[((password * alp_m_len) // bases[i]) % alp_m_len])
        skey_id = generator.prf(p_word.encode().hex(), nonce_1).hex()
        skey_id_e = generator.key_gen(skey_id, nonce_3, opt)
        IDi, hash_i = decrypt(e_k, iv, skey_id_e)
        expected_hash = generator.prf(skey_id, nonce_2_prt + IDi[8:]).hex()
        if hash_i == expected_hash:
            end = time.time()
            print('Passed passwords: ' + str(counter)
                  + ', speed: ' + str(round(counter / (end - start)))
                  + ' cand/s\n', 'Password recovered : ', p_word)
            return
    end = time.time()
    print('passwords: ' + str(counter) + ' speed: ' + str(round(counter / (end - start)))
          + ' cand/s\n', 'Password was not found :(')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-d',
                        '--dict',
                        type=pathlib.Path,
                        help='file with dictionary list')
    parser.add_argument('-m',
                        '--mask',
                        type=str,
                        required=True)
    parser.add_argument('file',
                        type=pathlib.Path)
    parser.add_argument('-o',
                        '--opt',
                        type=bool,
                        default=False,
                        help='set version optimised/non')
    process(parser.parse_args())
