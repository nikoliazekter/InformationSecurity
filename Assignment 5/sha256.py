class SHA256:

    def __init__(self):
        self.constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.mask = 0xffffffff

    def init_hash_value(self):
        return [0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19]

    def preprocess(self, bytes):
        binary_message = ''.join(bin(byte)[2:].zfill(8) for byte in bytes)
        l = len(binary_message)
        k = (447 - l) % 512
        padded_message = binary_message + '1' + '0' * k + bin(l)[2:].zfill(64)
        blocks = []
        for i in range(len(padded_message) // 512):
            binary_block = padded_message[i * 512:(i + 1) * 512]
            block = []
            for j in range(16):
                block.append(int(binary_block[j * 32: (j + 1) * 32], 2))
            blocks.append(block)
        return blocks

    def rotr(self, x, n):
        return (x >> n) | (x << (32 - n)) & self.mask

    def sigma0(self, x):
        return self.rotr(x, 7) ^ self.rotr(x, 18) ^ (x >> 3)

    def sigma1(self, x):
        return self.rotr(x, 17) ^ self.rotr(x, 19) ^ (x >> 10)

    def Sigma0(self, x):
        return self.rotr(x, 2) ^ self.rotr(x, 13) ^ self.rotr(x, 22)

    def Sigma1(self, x):
        return self.rotr(x, 6) ^ self.rotr(x, 11) ^ self.rotr(x, 25)

    def Ch(self, x, y, z):
        return (x & y) ^ ((~x & self.mask) & z)

    def Maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def hash(self, message):
        hash_value = self.init_hash_value()
        blocks = self.preprocess(message)
        for block in blocks:
            W = [x for x in block]
            for t in range(16, 64):
                new_w = (self.sigma1(W[t - 2]) + W[t - 7] + self.sigma0(W[t - 15]) + W[t - 16]) & self.mask
                W.append(new_w)

            a, b, c, d, e, f, g, h = hash_value
            for t in range(64):
                T1 = (h + self.Sigma1(e) + self.Ch(e, f, g) + self.constants[t] + W[t]) & self.mask
                T2 = (self.Sigma0(a) + self.Maj(a, b, c)) & self.mask
                h = g
                g = f
                f = e
                e = (d + T1) & self.mask
                d = c
                c = b
                b = a
                a = (T1 + T2) & self.mask
            hash_value = [(a + hash_value[0]) & self.mask,
                          (b + hash_value[1]) & self.mask,
                          (c + hash_value[2]) & self.mask,
                          (d + hash_value[3]) & self.mask,
                          (e + hash_value[4]) & self.mask,
                          (f + hash_value[5]) & self.mask,
                          (g + hash_value[6]) & self.mask,
                          (h + hash_value[7]) & self.mask]

        return int(''.join([hex(hv)[2:].zfill(8) for hv in hash_value]), 16)
