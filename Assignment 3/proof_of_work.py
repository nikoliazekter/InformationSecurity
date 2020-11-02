import time

from kupyna import Kupyna
from sha256 import SHA256

message = '000100'

sha = SHA256()
sha_hash = sha.hash(message)
start = time.time()
for i in range(10000000):
    hex_i = hex(i)[2:].zfill(len(message))
    if sha_hash == sha.hash(hex_i):
        print(f'SHA-256: proof of work took {time.time() - start} s.')
        break

kupyna256 = Kupyna(256)
kupyna256_hash = kupyna256.hash(message)
start = time.time()
for i in range(10000000):
    hex_i = hex(i)[2:].zfill(len(message))
    if kupyna256_hash == kupyna256.hash(hex_i):
        print(f'Kupyna-256: proof of work took {time.time() - start} s.')
        break

kupyna512 = Kupyna(512)
kupyna512_hash = kupyna512.hash(message)
start = time.time()
for i in range(10000000):
    hex_i = hex(i)[2:].zfill(len(message))
    if kupyna512_hash == kupyna512.hash(hex_i):
        print(f'Kupyna-512: proof of work took {time.time() - start} s.')
        break
