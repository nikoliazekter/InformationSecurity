from aes import AES
from helpers import *


class AES_CFB:

    def __init__(self, key, iv, s):
        self.n = 16
        self.s = s
        self.iv = list(hex_to_stream(iv))
        self.aes = AES(key)

    def encrypt(self, stream, padding=False):
        cipherblocks = []
        blocks = stream_to_blocks(stream, self.s, padding=padding)
        x = self.iv
        for block in blocks:
            y = self.aes.encipher(x)
            cipherblock = xor_bytes(block, y[:self.s])
            x = x[-(self.n - self.s):] + cipherblock
            cipherblocks.append(cipherblock)
        return blocks_to_stream(cipherblocks)

    def decrypt(self, cipherstream, padding=False):
        blocks = []
        cipherblocks = stream_to_blocks(cipherstream, self.s)
        x = self.iv
        for cipherblock in cipherblocks:
            y = self.aes.encipher(x)
            block = xor_bytes(cipherblock, y[:self.s])
            x = x[-(self.n - self.s):] + cipherblock
            blocks.append(block)
        return blocks_to_stream(blocks, padding=padding)
