import random

from sha256 import SHA256


class DigitalSignature:

    def __init__(self, ec, base_point):
        self.ec = ec
        self.base_point = base_point
        self.len_n = self.ec.n.bit_length()
        self.mask = (1 << (self.len_n - 1)) - 1
        self.hash_func = SHA256().hash

    def gen_private_key(self):
        return self.random_int(minimum=1)

    def gen_public_key(self, d):
        return self.ec.multiple(self.ec.negate_point(self.base_point), d)

    def presignature(self):
        while True:
            e = self.random_int(minimum=1)
            x, y = self.ec.multiple(self.base_point, e)
            if x != 0:
                return e, x

    def sign(self, message, d, sig_len=512):
        if sig_len % 16 != 0 or sig_len < 2 * self.len_n:
            raise RuntimeError('Signature length should be multiple of 16 and >= 2*L(n)')

        h = self.hash_func(message) & self.ec.gf.mask
        if h == 0:
            h = 1

        while True:
            e, f_e = self.presignature()
            r = self.ec.gf.mul(h, f_e) & self.mask
            if r == 0:
                continue
            s = (e + d * r) % self.ec.n
            if s != 0:
                return message, self.to_signature(r, s, sig_len)

    def verify(self, message, signature, Q, sig_len=512):
        if sig_len % 16 != 0 or sig_len < 2 * self.len_n:
            raise RuntimeError('Signature length should be multiple of 16 and >= 2*L(n)')

        h = self.hash_func(message) & self.ec.gf.mask
        if h == 0:
            h = 1

        r, s = self.to_pair(signature, sig_len)
        if not (0 < r < self.ec.n) or not (0 < s < self.ec.n):
            return False

        x, y = self.ec.add_points(
            self.ec.multiple(self.base_point, s),
            self.ec.multiple(Q, r))
        r2 = self.ec.gf.mul(h, x) & self.mask
        return r == r2

    def to_signature(self, r, s, sig_len=512):
        l = sig_len // 2
        return (s << l) ^ r

    def to_pair(self, signature, sig_len=512):
        l = sig_len // 2
        signature_mask = (1 << l) - 1
        r = signature & signature_mask
        s = (signature >> l) & signature_mask
        return r, s

    def random_int(self, minimum=1):
        return random.randint(minimum, self.mask)
