from aes import AES
from helpers import *


class AES_CTR:

    def __init__(self, key, initial_counter):
        self.n = 16
        self.counter = list(hex_to_stream(initial_counter))
        self.aes = AES(key)

    def inc_counter(self):
        for i in range(len(self.counter) - 1, -1, -1):
            self.counter[i] = np.uint8(self.counter[i] + 1)
            if self.counter[i] != 0:
                break

    def encrypt(self, stream):
        cipherblocks = []
        blocks = stream_to_blocks(stream, self.n)
        for block in blocks:
            y = self.aes.encipher(self.counter)
            cipherblock = xor_bytes(block, y[:len(block)])
            self.inc_counter()
            cipherblocks.append(cipherblock)
        return blocks_to_stream(cipherblocks)

    def decrypt(self, cipherstream):
        blocks = []
        cipherblocks = stream_to_blocks(cipherstream, self.n)
        for cipherblock in cipherblocks:
            y = self.aes.encipher(self.counter)
            block = xor_bytes(cipherblock, y[:len(cipherblock)])
            self.inc_counter()
            blocks.append(block)
        return blocks_to_stream(blocks)
