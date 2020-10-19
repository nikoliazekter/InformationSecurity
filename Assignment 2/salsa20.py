import itertools


class Salsa20:

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.mask = 0xffffffff

    def rotate_left(self, n, d):
        return (n << d) & self.mask | (n >> (32 - d))

    def add_mod32(self, a, b):
        return (a + b) & self.mask

    def stream_to_salsa_blocks(self, stream):
        pass

    def quarter_round(self, a, b, c, d):
        b ^= self.rotate_left(self.add_mod32(a, d), 7)
        c ^= self.rotate_left(self.add_mod32(b, a), 9)
        d ^= self.rotate_left(self.add_mod32(c, b), 13)
        a ^= self.rotate_left(self.add_mod32(d, c), 18)
        return a, b, c, d

    def row_round(self, x):
        z = [0] * 16
        z[0], z[1], z[2], z[3] = self.quarter_round(x[0], x[1], x[2], x[3])
        z[5], z[6], z[7], z[4] = self.quarter_round(x[5], x[6], x[7], x[4])
        z[10], z[11], z[8], z[9] = self.quarter_round(x[10], x[11], x[8], x[9])
        z[15], z[12], z[13], z[14] = self.quarter_round(x[15], x[12], x[13], x[14])
        return z

    def column_round(self, x):
        z = [0] * 16
        z[0], z[4], z[8], z[12] = self.quarter_round(x[0], x[4], x[8], x[12])
        z[5], z[9], z[13], z[1] = self.quarter_round(x[5], x[9], x[13], x[1])
        z[10], z[14], z[2], z[6] = self.quarter_round(x[10], x[14], x[2], x[6])
        z[15], z[3], z[7], z[11] = self.quarter_round(x[15], x[3], x[7], x[11])
        return z

    def double_round(self, x):
        return self.row_round(self.column_round(x))

    def little_endian(self, a, b, c, d):
        return d << 24 | c << 16 | b << 8 | a

    def inv_little_endian(self, x):
        a = x & 0x000000ff
        b = (x & 0x0000ff00) >> 8
        c = (x & 0x00ff0000) >> 16
        d = (x & 0xff000000) >> 24
        return a, b, c, d

    def hash(self, x):
        x = [self.little_endian(*x[4 * i:4 * i + 4]) for i in range(16)]
        z = x
        for i in range(10):
            z = self.double_round(z)
        result = []
        for i in range(16):
            result += self.inv_little_endian(self.add_mod32(z[i], x[i]))
        return result

    def expand(self, k, n):
        if len(k) == 16:
            t0 = [101, 120, 112, 97]
            t1 = [110, 100, 32, 49]
            t2 = [54, 45, 98, 121]
            t3 = [116, 101, 32, 107]
            return self.hash(list(itertools.chain(t0, k, t1, n, t2, k, t3)))
        if len(k) == 32:
            t0 = [101, 120, 112, 97]
            t1 = [110, 100, 32, 51]
            t2 = [50, 45, 98, 121]
            t3 = [116, 101, 32, 107]
            return self.hash(list(itertools.chain(t0, k[:16], t1, n, t2, k[16:], t3)))

    def inc_counter(self, counter):
        for i in range(len(counter)):
            counter[i] = (counter[i] + 1) % 256
            if counter[i] != 0:
                break

    def encrypt(self, stream):
        counter = [0] * 8
        cipher = []
        sequence = None
        for i, byte in enumerate(stream):
            if i % 8 == 0:
                sequence = self.expand(self.key, self.nonce + counter)
                self.inc_counter(counter)
            cipher.append(sequence[i % 8] ^ byte)
        return cipher

    def decrypt(self, cipherstream):
        counter = [0] * 8
        m = []
        sequence = None
        for i, byte in enumerate(cipherstream):
            if i % 8 == 0:
                sequence = self.expand(self.key, self.nonce + counter)
                self.inc_counter(counter)
            m.append(sequence[i % 8] ^ byte)
        return m
