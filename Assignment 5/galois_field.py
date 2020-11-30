import random


class GF:

    def __init__(self, m=179, l=4, j=2, k=1):
        self.m = m
        self.f = (1 << m) + (1 << l) + (1 << j) + (1 << k) + 1
        self.mask = (1 << m) - 1

    def add(self, a, b):
        return a ^ b

    def mul(self, a, b):
        p = 0
        while a and b:
            if b & 1 == 1:
                p ^= a
            b >>= 1
            carry = a >> (self.m - 1)
            a = (a << 1) & self.mask
            if carry == 1:
                a ^= self.mask & self.f
        return p

    def square(self, a):
        return self.mul(a, a)

    def pow(self, a, n):
        r = 1
        while n > 0:
            if n & 1 == 1:
                r = self.mul(a, r)
            a = self.square(a)
            n = n >> 1
        return r

    def inv(self, a):
        return self.pow(a, (1 << self.m) - 2)

    def div(self, a, b):
        return self.mul(a, self.inv(b))

    def trace(self, a):
        t = a
        for _ in range(self.m - 1):
            t = self.add(self.square(t), a)
        return t

    def half_trace(self, a):
        t = a
        for i in range((self.m - 1) // 2):
            t = self.add(self.pow(t, 4), a)
        return t

    def solve_quadratic_eq(self, u, w):
        if u == 0:
            z = self.pow(w, 1 << (self.m - 1))
            return z, 1
        if w == 0:
            return 0, 2
        v = self.mul(w, self.square(self.inv(u)))
        if self.trace(v) == 1:
            return 0, 0
        t = self.half_trace(v)
        return self.mul(t, u), 2

    def random(self, minimum=0):
        return random.randint(minimum, self.mask)
