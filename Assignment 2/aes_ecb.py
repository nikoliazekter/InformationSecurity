from aes import AES
from helpers import *


class AES_ECB:

    def __init__(self, key):
        self.n = 16
        self.aes = AES(key)

    def encrypt(self, stream, padding=False):
        cipherblocks = []
        blocks = stream_to_blocks(stream, self.n, padding=padding)
        for block in blocks:
            cipherblocks.append(self.aes.encipher(block))
        return blocks_to_stream(cipherblocks)

    def decrypt(self, cipherstream, padding=False):
        blocks = []
        cipherblocks = stream_to_blocks(cipherstream, self.n)
        for cipherblock in cipherblocks:
            blocks.append(self.aes.decipher(cipherblock))
        return blocks_to_stream(blocks, padding=padding)
