import argparse
import pathlib
import string
import time
import generator
from Crypto.Cipher import DES3
from Crypto.Cipher import AES

SHA1_HASH_LEN = 20
BOOST = 2
IDii_SIZE = 24

MASK = ['a', 'd', 'l', 'u']
IDii_pref = "0800000c"
IDii_payload_size = 4
HASH_I_payload_size = 4


def get_hashmac_output_size(hash):
    return SHA1_HASH_LEN*2


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


def rebuild_file(file):
    with open(file, "r") as f:
        text = f.read()
        text_chunks = text.split('*')
        if len(text_chunks) == 11:
            hash = get_hash_algo(text_chunks[0])
            algo = get_enc_algo(text_chunks[1])
            N_i = text_chunks[2]
            N_r = text_chunks[3]
            G_x = text_chunks[4]
            G_y = text_chunks[5]
            G_xy = text_chunks[6]
            Ci = text_chunks[7]
            Cr = text_chunks[8]
            SAi = text_chunks[9]
            E_k = text_chunks[10]

            N_THIRD = G_xy + Ci + Cr
            N_SECOND_without_IDii_b = G_x + G_y + Ci + Cr + SAi
            N_FIRST = N_i + N_r

            iv = generator.get_iv_for_mode(algo, G_x + G_y)

            return hash, algo, N_FIRST, N_SECOND_without_IDii_b, N_THIRD, iv, E_k
        else:
            print("Incorrect format file for application.")
            exit(0)


def alphabet(letter):
    if letter == 'a':
        return list(string.ascii_letters) + list(string.digits + '!')
    if letter == 'l':
        return list(string.ascii_lowercase)
    if letter == 'u':
        return list(string.ascii_uppercase)
    if letter == 'd':
        return list(string.digits + '!')


def check_mask(mask):
    result = True
    for mask_parameter in mask:
        result &= mask_parameter in MASK
    return result


def gen_passwords(mask, dict_file):
    aphs = [alphabet(letter) for letter in mask]
    with open(dict_file, "r") as f:
        res = f.readlines()
    words = []
    for word in res:
        if word[-1] == '\n':
            words.append(word[:-1])
        else:
            words.append(word)
    return [words] + aphs


def get_encoder(algo, iv, key):
    if algo == '3des':
        cipher = DES3.new(key, DES3.MODE_CBC, IV=iv)
        return cipher
    if algo == 'aes128':
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        return cipher
    if algo == 'aes192':
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        return cipher
    else:
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        return cipher


def ords(alphabets):
    passwords_count = 1
    ords_bases = []

    for custom_alphabet in alphabets:
        passwords_count *= len(custom_alphabet)

    for i in range(len(alphabets)):
        if i == 0:
            ords_bases.append(len(alphabets[i]))
        else:
            ords_bases.append(ords_bases[i-1] * len(alphabets[i]))

    return ords_bases, passwords_count


def process(args):
    if check_mask(args.mask):
        passwords = gen_passwords(args.mask, args.dict)
        hash, algo, nonce_1, nonce_2_prt, nonce_3, iv, e_k = rebuild_file(args.file)
        brute(passwords, hash, algo, nonce_1, nonce_2_prt, nonce_3, e_k, iv, args.opt)
    else:
        print("Incorrect mask parameters!")
        exit(0)


def decrypt(hash, algo, e_k, iv, s_key_id_e):
    text = get_encoder(algo, iv, s_key_id_e).decrypt(bytes.fromhex(e_k)).hex()

    sep = get_hashmac_output_size(hash)
    return text[:IDii_SIZE], text[(IDii_SIZE + (HASH_I_payload_size*2)):(IDii_SIZE + (HASH_I_payload_size*2) + sep)]


def brute(passwords_list, hash, algo, nonce_1, nonce_2_prt, nonce_3, e_k, iv, opt):
    bases, passwords = ords(passwords_list)

    global_counter = 0
    start = time.time()
    for password in range(passwords):
        password_word = ''
        for i in range(len(bases)):
            global_counter +=1
            mask_alphabet = passwords_list[i]
            len_alphabet = len(mask_alphabet)
            if i == 0:
                password_word += mask_alphabet[password % bases[i]]
            else:
                password_word += mask_alphabet[((password * len_alphabet) // bases[i]) % len_alphabet]
        s_key_id = generator.prf(password_word.encode().hex(), nonce_1).hex()
        s_key_id_e = generator.key_gen(s_key_id, nonce_3, opt)
        ID, hash_i = decrypt(hash, algo, e_k, iv, s_key_id_e)
        hash_exp = generator.prf(s_key_id, nonce_2_prt + ID[(IDii_payload_size*2):]).hex()
        if hash_i == hash_exp:
            end = time.time()
            print('passwords: ' + str(global_counter) + ' speed: ' + str(round(global_counter / (end - start))) + ' cand/sc\n')
            print('Password recovered! Password : ', password_word)
            return
    end = time.time()
    print('passwords: ' + str(global_counter) + ' speed: ' + str(round(global_counter / (end - start))) + ' cand/sc\n')
    print('The password was not found during the enumeration.')


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
