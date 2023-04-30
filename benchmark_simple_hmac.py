import pbkdf2
import random_gen


def start_test():
    password = bytearray(random_gen.generate_bytes_with_length(16))
    message = bytearray(random_gen.generate_bytes())
    pbkdf2_sim = pbkdf2.gen_passw(password, message, 30, 52)


if __name__ == '__main__':
    start_test()
