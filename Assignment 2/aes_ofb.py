from aes import AES
from helpers import *


class AES_OFB:

    def __init__(self, key, iv):
        self.n = 16
        self.iv = list(hex_to_stream(iv))
        self.aes = AES(key)

    def encrypt(self, stream):
        cipherblocks = []
        blocks = stream_to_blocks(stream, self.n)
        x = self.iv
        for block in blocks:
            y = self.aes.encipher(x)
            cipherblock = xor_bytes(block, y[:len(block)])
            x = y
            cipherblocks.append(cipherblock)
        return blocks_to_stream(cipherblocks)

    def decrypt(self, cipherstream):
        blocks = []
        cipherblocks = stream_to_blocks(cipherstream, self.n)
        x = self.iv
        for cipherblock in cipherblocks:
            y = self.aes.encipher(x)
            block = xor_bytes(cipherblock, y[:len(cipherblock)])
            x = y
            blocks.append(block)
        return blocks_to_stream(blocks)
