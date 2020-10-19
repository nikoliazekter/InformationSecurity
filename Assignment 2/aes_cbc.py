from aes import AES
from helpers import *


class AES_CBC:

    def __init__(self, key, iv):
        self.n = 16
        self.iv = list(hex_to_stream(iv))
        self.aes = AES(key)

    def encrypt(self, stream, padding=False):
        cipherblocks = []
        blocks = stream_to_blocks(stream, self.n, padding=padding)
        last_block = self.iv
        for block in blocks:
            cipherblock = self.aes.encipher(xor_bytes(block, last_block))
            last_block = cipherblock
            cipherblocks.append(cipherblock)
        return blocks_to_stream(cipherblocks)

    def decrypt(self, cipherstream, padding=False):
        blocks = []
        cipherblocks = stream_to_blocks(cipherstream, self.n)
        last_block = self.iv
        for cipherblock in cipherblocks:
            block = xor_bytes(self.aes.decipher(cipherblock), last_block)
            last_block = cipherblock
            blocks.append(block)
        return blocks_to_stream(blocks, padding=padding)
