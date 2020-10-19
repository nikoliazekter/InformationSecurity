class RC4:

    def __init__(self, key):
        self.key = key
        key_length = len(self.key)

        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def encrypt(self, stream):
        i = 0
        j = 0
        result = []
        for byte in stream:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            t = (self.S[i] + self.S[j]) % 256
            result.append(byte ^ self.S[t])
        return result

    def decrypt(self, cipherstream):
        i = 0
        j = 0
        result = []
        for byte in cipherstream:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            t = (self.S[i] + self.S[j]) % 256
            result.append(byte ^ self.S[t])
        return result
