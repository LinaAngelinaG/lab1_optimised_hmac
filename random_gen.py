from random import random


def generate_bytes():
    size = random.randrange(1, 1000)
    for _ in range(size):
        yield random.getrandbits(8)


def generate_bytes_with_length(len):
    for _ in range(len):
        yield random.getrandbits(8)