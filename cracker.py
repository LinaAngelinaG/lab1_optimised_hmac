import argparse
import pathlib
import string
import time
import generator
from Crypto.Cipher import DES3

SHA1_HASH_LEN = 20
BOOST = 2
IDii_SIZE = 24

MASK = ['a', 'd', 'l', 'u']
prefix = "0800000c"
HASH_len = 4
IDii_len = 4


def get_hashmac_output_size(hash):
    return SHA1_HASH_LEN*2


def gain_params_from_file(file):
    with open(file, "r") as f:
        text = f.read()
        bites = text.split('*')
        if len(bites) == 11:
            hash = get_hash_algo(bites[0])
            algo = get_enc_algo(bites[1])

            N_i = bites[2]
            N_r = bites[3]
            G_x = bites[4]
            G_y = bites[5]
            G_xy = bites[6]
            Ci = bites[7]
            Cr = bites[8]
            SAi = bites[9]

            N_3 = G_xy + Ci + Cr
            N_2 = G_x + G_y + Ci + Cr + SAi
            N_1 = N_i + N_r

            E_k = bites[10]

            iv = generator.get_iv_for_mode(algo, G_x + G_y)

            return hash, algo, N_1, N_2, N_3, iv, E_k
        else:
            print("Ivalid file presented")
            exit(0)


def get_enc_algo(enc_id):
    if enc_id == '5':
        return '3des'
    elif enc_id == '7':
        return 'aes128'
    elif enc_id == '8':
        return 'aes192'
    elif enc_id == '9':
        return 'aes256'
    else:
        print("Invalid encryption algorithm.")
        exit(1)


def get_hash_algo(hash_id):
    if hash_id == '1':
        return 'md5'
    elif hash_id == '2':
        return 'sha1'
    else:
        print("Invalid hash mode")
        exit(1)


def gain_list_from_mask(letter):
    if letter == 'a':
        return list(string.ascii_letters) + list(string.digits + '!')
    if letter == 'l':
        return list(string.ascii_lowercase)
    if letter == 'u':
        return list(string.ascii_uppercase)
    if letter == 'd':
        return list(string.digits + '!')


def is_mask_valid(mask):
    for mask_parameter in mask:
        if mask_parameter not in MASK:
            return False
    return True


def gen_passwords(mask, dict_file):
    list_passw = [gain_list_from_mask(letter) for letter in mask]
    with open(dict_file, "r") as f:
        res = f.readlines()
    passws = []
    for word in res:
        if word[-1] == '\n':
            passws.append(word[:-1])
        else:
            passws.append(word)
    return [passws] + list_passw


def get_encoder(iv, key):
    return DES3.new(key, DES3.MODE_CBC, IV=iv)


def get_pare(passw_list):
    passwords_count = 1
    ords_bases = []

    for custom_alphabet in passw_list:
        passwords_count *= len(custom_alphabet)

    for i in range(len(passw_list)):
        if i == 0:
            ords_bases.append(len(passw_list[i]))
        else:
            ords_bases.append(ords_bases[i-1] * len(passw_list[i]))

    return ords_bases, passwords_count


def process(args):
    if is_mask_valid(args.mask):
        passwords = gen_passwords(args.mask, args.dict)
        hash, algo, nonce_1, nonce_2_prt, nonce_3, iv, e_k = gain_params_from_file(args.file)
        brute(passwords, hash, algo, nonce_1, nonce_2_prt, nonce_3, e_k, iv, args.opt)
    else:
        print("Incorrect mask parameters!")
        exit(0)


def decrypt(hash, e_k, iv, skey_id_e):
    text = get_encoder(iv, skey_id_e).decrypt(bytes.fromhex(e_k)).hex()
    sep = get_hashmac_output_size(hash)
    return text[:IDii_SIZE], text[(IDii_SIZE + (HASH_len * 2)):(IDii_SIZE + (HASH_len * 2) + sep)]


def brute(passwords_list, hash, algo, nonce_1, nonce_2_prt, nonce_3, e_k, iv, opt):
    bases, passwords = get_pare(passwords_list)

    counter = 0
    start = time.time()
    for password in range(passwords):
        p_word = ''
        for i in range(len(bases)):
            counter +=1
            alp_m = passwords_list[i]
            alp_m_len = len(alp_m)
            if i == 0:
                p_word += alp_m[password % bases[i]]
            else:
                p_word += alp_m[((password * alp_m_len) // bases[i]) % alp_m_len]
        skey_id = generator.prf(p_word.encode().hex(), nonce_1).hex()
        skey_id_e = generator.key_gen(skey_id, nonce_3, opt)
        IDi, hash_i = decrypt(hash, e_k, iv, skey_id_e)
        expected_hash = generator.prf(skey_id, nonce_2_prt + IDi[(IDii_len * 2):]).hex()
        if hash_i == expected_hash:
            end = time.time()
            print('Passed passwords: ' + str(counter) + ', speed: ' + str(round(counter / (end - start))) + ' cand/s\n','Password recovered : ', p_word)
            return
    end = time.time()
    print('passwords: ' + str(counter) + ' speed: ' + str(round(counter / (end - start))) + ' cand/s\n','Password was not found :(')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-d',
                        '--dict',
                        type=pathlib.Path,
                        action='store',
                        help='file with dictionary list')
    parser.add_argument('-m',
                        '--mask',
                        action='store',
                        type=str,
                        required=True,
                        help=
                        '''set mask for cracking password 
                            a – u+l+d; 
                            d – digits; 
                            l – lower letters; 
                            u – upper letters. 
                        ''')
    parser.add_argument('file',
                        type=pathlib.Path,
                        action='store',
                        help='file with all neccesary info')
    parser.add_argument('-o',
                        '--opt',
                        type=bool,
                        default=False,
                        help='set version optimised/non')
    process(parser.parse_args())
