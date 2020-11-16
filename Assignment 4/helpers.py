import math
import random


def miller_rabin(n, k):
    if n < 2:
        return False
    if n in {2, 3}:
        return True

    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d = d // 2

    for j in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def new_prime(num_bits, k=40):
    assert num_bits >= 2

    l, h = 2 ** (num_bits - 1), 2 ** num_bits - 1
    while True:
        a = random.randint(l, h)
        if miller_rabin(a, k):
            return a


def mul_inv(a, m):
    m0 = m
    x0, x1 = 0, 1
    if m == 1:
        return 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def byte_length(n):
    return math.ceil(n.bit_length() / 8)


def bytes_to_int(bytes):
    return int.from_bytes(bytes, 'big')


def int_to_bytes(n, fill_size=-1):
    bytes_required = fill_size if fill_size != -1 else byte_length(n)
    return n.to_bytes(bytes_required, 'big')


def xor_bytes(bytes1, bytes2):
    assert len(bytes1) == len(bytes2)
    return bytes(a ^ b for (a, b) in zip(bytes1, bytes2))
