import time

from kupyna import Kupyna
from sha256 import SHA256


def proof_of_work(hash_function, prefix, n):
    mask = int('1' * n, 2)
    i = 0
    start = time.time()
    while True:
        hex_i = hex(i)[2:]
        hex_i = '0' * (len(hex_i) % 2) + hex_i
        message = prefix + hex_i
        res = hash_function(message) & mask
        if res == 0:
            # print(i)
            break
        i += 1
    return time.time() - start


prefix = '0102030405'
sha256 = SHA256()
kupyna256 = Kupyna(256)
kupyna512 = Kupyna(512)
for n in range(2, 20):
    print(f'Number of zero bits: {n}')
    print(f'SHA-256 time: {proof_of_work(sha256.hash, prefix, n):.4} s')
    print(f'Kupyna-256 time: {proof_of_work(kupyna256.hash, prefix, n):.4} s')
    print(f'Kupyna-512 time: {proof_of_work(kupyna512.hash, prefix, n):.4} s')
