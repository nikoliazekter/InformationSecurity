import math
import random

from helpers import new_prime, mul_inv, bytes_to_int, int_to_bytes


def _choose_e(phi_n):
    while True:
        e = random.randint(3, phi_n - 1)
        if math.gcd(e, phi_n) == 1:
            return e


def new_key_pair(num_bits):
    p = new_prime(num_bits)
    q = new_prime(num_bits)
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = _choose_e(phi_N)
    d = mul_inv(e, phi_N)
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    q_inv = mul_inv(q, p)
    return (N, e), (p, q, d_p, d_q, q_inv)


def encrypt(plaintext, public_key):
    N, e = public_key
    m = bytes_to_int(plaintext)
    assert m < N
    c = pow(m, e, N)
    return int_to_bytes(c)


def decrypt(ciphertext, private_key):
    p, q, d_p, d_q, q_inv = private_key
    c = bytes_to_int(ciphertext)
    m1 = pow(c, d_p, p)
    m2 = pow(c, d_q, q)
    h = (q_inv * (m1 - m2)) % p
    m = (m2 + h * q) % (p * q)
    return int_to_bytes(m)
