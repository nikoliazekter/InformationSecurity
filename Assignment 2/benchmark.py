import random
from time import time

import numpy as np

from aes_cbc import AES_CBC
from aes_cfb import AES_CFB
from aes_ctr import AES_CTR
from aes_ecb import AES_ECB
from aes_ofb import AES_OFB
from rc4 import RC4
from salsa20 import Salsa20

rc4 = RC4([random.randint(0, 255) for _ in range(256)])

key = [random.randint(0, 255) for _ in range(32)]
nonce = [random.randint(0, 255) for _ in range(8)]
salsa20 = Salsa20(key, nonce)

key = '2b7e151628aed2a6abf7158809cf4f3c'
iv = '000102030405060708090a0b0c0d0e0f'
aes_ecb = AES_ECB(key)
aes_cbc = AES_CBC(key, iv)
aes_ofb = AES_OFB(key, iv)
aes_ctr = AES_CTR(key, 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
aes_cfb1 = AES_CFB(key, iv, 1)
aes_cfb4 = AES_CFB(key, iv, 4)
aes_cfb8 = AES_CFB(key, iv, 8)

message_length = 100000

message = (np.uint8(x) for x in range(message_length))
start = time()
rc4.encrypt(message)
print(f'RC4: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
salsa20.encrypt(message)
print(f'Salsa20: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_ecb.encrypt(message)
print(f'AES ECB: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_cbc.encrypt(message)
print(f'AES CBC: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_ofb.encrypt(message)
print(f'AES OFB: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_ctr.encrypt(message)
print(f'AES CTR: {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_cfb1.encrypt(message)
print(f'AES CFB (s={aes_cfb1.s}): {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_cfb4.encrypt(message)
print(f'AES CFB (s={aes_cfb4.s}): {time() - start} s')
message = (np.uint8(x) for x in range(message_length))
start = time()
aes_cfb8.encrypt(message)
print(f'AES CFB (s={aes_cfb8.s}): {time() - start} s')