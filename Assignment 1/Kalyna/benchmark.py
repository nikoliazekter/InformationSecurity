import time

from kalyna import *

key22 = to_words('000102030405060708090A0B0C0D0E0F')
key24 = to_words('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
key88 = to_words(
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')

message = [x for x in range(100000 // 8)]  # 100 KB

ctx = init_context(128, 128)
kalyna_key_expand(ctx, key22)
blocks = to_blocks(message, 128)
start = time.time()
for block in blocks:
    kalyna_encipher(ctx, block)
print(f'Encryption of 100 KB (Nb={ctx.Nb}, Nk={ctx.Nk}, Nr={ctx.Nr}) takes: {time.time() - start} s.')

ctx = init_context(128, 256)
kalyna_key_expand(ctx, key24)
blocks = to_blocks(message, 128)
start = time.time()
for block in blocks:
    kalyna_encipher(ctx, block)
print(f'Encryption of 100 KB (Nb={ctx.Nb}, Nk={ctx.Nk}, Nr={ctx.Nr}) takes: {time.time() - start} s.')

ctx = init_context(512, 512)
kalyna_key_expand(ctx, key88)
blocks = to_blocks(message, 512)
start = time.time()
for block in blocks:
    kalyna_encipher(ctx, block)
print(f'Encryption of 100 KB (Nb={ctx.Nb}, Nk={ctx.Nk}, Nr={ctx.Nr}) takes: {time.time() - start} s.')
