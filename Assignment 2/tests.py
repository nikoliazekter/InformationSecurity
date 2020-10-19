import random
import unittest

from aes import AES
from aes_cbc import AES_CBC
from aes_cfb import AES_CFB
from aes_ctr import AES_CTR
from aes_ecb import AES_ECB
from aes_ofb import AES_OFB
from helpers import *
from rc4 import RC4
from salsa20 import Salsa20


class TestAES(unittest.TestCase):

    def test_encipher(self):
        plaintext = '00112233445566778899aabbccddeeff'
        key = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES(key)
        ciphertext = stream_to_hex(encrypter.encipher(list(hex_to_stream(plaintext))))
        self.assertEqual(ciphertext, '69c4e0d86a7b0430d8cdb78070b4c55a')

    def test_decipher(self):
        ciphertext = '69c4e0d86a7b0430d8cdb78070b4c55a'
        key = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES(key)
        deciphered = stream_to_hex(encrypter.decipher(list(hex_to_stream(ciphertext))))
        self.assertEqual(deciphered, '00112233445566778899aabbccddeeff')


class TestAES_ECB(unittest.TestCase):

    def test_encipher(self):
        plaintext = '00112233445566778899aabbccddeeff'
        key = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_ECB(key)
        ciphertext = stream_to_hex(encrypter.encrypt(hex_to_stream(plaintext)))
        self.assertEqual(ciphertext, '69c4e0d86a7b0430d8cdb78070b4c55a')

    def test_decipher(self):
        ciphertext = '69c4e0d86a7b0430d8cdb78070b4c55a'
        key = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_ECB(key)
        deciphered = stream_to_hex(encrypter.decrypt(hex_to_stream(ciphertext)))
        self.assertEqual(deciphered, '00112233445566778899aabbccddeeff')


class TestAES_CBC(unittest.TestCase):

    def test_encipher(self):
        plaintext = '6bc1bee22e409f96e93d7e117393172a'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_CBC(key, iv)
        ciphertext = stream_to_hex(encrypter.encrypt(hex_to_stream(plaintext)))
        self.assertEqual(ciphertext, '7649abac8119b246cee98e9b12e9197d')

    def test_decipher(self):
        ciphertext = '7649abac8119b246cee98e9b12e9197d'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_CBC(key, iv)
        deciphered = stream_to_hex(encrypter.decrypt(hex_to_stream(ciphertext)))
        self.assertEqual(deciphered, '6bc1bee22e409f96e93d7e117393172a')


class TestAES_CFB(unittest.TestCase):

    def test_encipher(self):
        plaintext = '6bc1bee22e409f96e93d7e117393172aae2d'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_CFB(key, iv, 1)
        ciphertext = stream_to_hex(encrypter.encrypt(hex_to_stream(plaintext)))
        self.assertEqual(ciphertext, '3b79424c9c0dd436bace9e0ed4586a4f32b9')

    def test_decipher(self):
        ciphertext = '3b79424c9c0dd436bace9e0ed4586a4f32b9'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_CFB(key, iv, 1)
        deciphered = stream_to_hex(encrypter.decrypt(hex_to_stream(ciphertext)))
        self.assertEqual(deciphered, '6bc1bee22e409f96e93d7e117393172aae2d')


class TestAES_OFB(unittest.TestCase):

    def test_encipher(self):
        plaintext = '6bc1bee22e409f96e93d7e117393172a'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_OFB(key, iv)
        ciphertext = stream_to_hex(encrypter.encrypt(hex_to_stream(plaintext)))
        self.assertEqual(ciphertext, '3b3fd92eb72dad20333449f8e83cfb4a')

    def test_decipher(self):
        ciphertext = '3b3fd92eb72dad20333449f8e83cfb4a'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        iv = '000102030405060708090a0b0c0d0e0f'
        encrypter = AES_OFB(key, iv)
        deciphered = stream_to_hex(encrypter.decrypt(hex_to_stream(ciphertext)))
        self.assertEqual(deciphered, '6bc1bee22e409f96e93d7e117393172a')


class TestAES_CTR(unittest.TestCase):

    def test_encipher(self):
        plaintext = '6bc1bee22e409f96e93d7e117393172a'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        initial_counter = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        encrypter = AES_CTR(key, initial_counter)
        ciphertext = stream_to_hex(encrypter.encrypt(hex_to_stream(plaintext)))
        self.assertEqual(ciphertext, '874d6191b620e3261bef6864990db6ce')

    def test_decipher(self):
        ciphertext = '874d6191b620e3261bef6864990db6ce'
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        initial_counter = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        encrypter = AES_CTR(key, initial_counter)
        deciphered = stream_to_hex(encrypter.decrypt(hex_to_stream(ciphertext)))
        self.assertEqual(deciphered, '6bc1bee22e409f96e93d7e117393172a')


class TestRC4(unittest.TestCase):
    def test_encrypt(self):
        message = [random.randint(0, 255) for i in range(1000)]
        key = [random.randint(0, 255) for i in range(256)]
        encrypter = RC4(key)

        decrypter = RC4(key)
        self.assertEqual(decrypter.decrypt(encrypter.encrypt(message)), message)


class TestSalsa20(unittest.TestCase):

    def test_quarter_round(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.quarter_round(0x00000000, 0x00000000, 0x00000000, 0x00000000),
                         (0x00000000, 0x00000000, 0x00000000, 0x00000000))
        self.assertEqual(salsa.quarter_round(0x00000001, 0x00000000, 0x00000000, 0x00000000),
                         (0x08008145, 0x00000080, 0x00010200, 0x20500000))
        self.assertEqual(salsa.quarter_round(0x00000000, 0x00000001, 0x00000000, 0x00000000),
                         (0x88000100, 0x00000001, 0x00000200, 0x00402000))
        self.assertEqual(salsa.quarter_round(0x00000000, 0x00000000, 0x00000001, 0x00000000),
                         (0x80040000, 0x00000000, 0x00000001, 0x00002000))
        self.assertEqual(salsa.quarter_round(0x00000000, 0x00000000, 0x00000000, 0x00000001),
                         (0x00048044, 0x00000080, 0x00010000, 0x20100001))
        self.assertEqual(salsa.quarter_round(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137),
                         (0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3))
        self.assertEqual(salsa.quarter_round(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b),
                         (0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c))

    def test_row_round(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.row_round([0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                          0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                          0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                          0x00000001, 0x00000000, 0x00000000, 0x00000000]),
                         [0x08008145, 0x00000080, 0x00010200, 0x20500000,
                          0x20100001, 0x00048044, 0x00000080, 0x00010000,
                          0x00000001, 0x00002000, 0x80040000, 0x00000000,
                          0x00000001, 0x00000200, 0x00402000, 0x88000100])
        self.assertEqual(salsa.row_round([0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                                          0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                                          0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                                          0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a]),
                         [0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
                          0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
                          0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
                          0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d])

    def test_column_round(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.column_round([0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000001, 0x00000000, 0x00000000, 0x00000000]),
                         [0x10090288, 0x00000000, 0x00000000, 0x00000000,
                          0x00000101, 0x00000000, 0x00000000, 0x00000000,
                          0x00020401, 0x00000000, 0x00000000, 0x00000000,
                          0x40a04001, 0x00000000, 0x00000000, 0x00000000])
        self.assertEqual(salsa.column_round([0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                                             0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                                             0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                                             0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a]),
                         [0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
                          0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
                          0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
                          0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8])

    def test_double_round(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.double_round([0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000]),
                         [0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
                          0x08000090, 0x02402200, 0x00004000, 0x00800000,
                          0x00010200, 0x20400000, 0x08008104, 0x00000000,
                          0x20500000, 0xa0000040, 0x0008180a, 0x612a8020])
        self.assertEqual(salsa.double_round([0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
                                             0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
                                             0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
                                             0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1]),
                         [0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
                          0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
                          0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
                          0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277])

    def test_little_endian(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.little_endian(0, 0, 0, 0), 0x00000000)
        self.assertEqual(salsa.little_endian(86, 75, 30, 9), 0x091e4b56)
        self.assertEqual(salsa.little_endian(255, 255, 255, 250), 0xfaffffff)

    def test_inv_little_endian(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.inv_little_endian(0x00000000), (0, 0, 0, 0))
        self.assertEqual(salsa.inv_little_endian(0x091e4b56), (86, 75, 30, 9))
        self.assertEqual(salsa.inv_little_endian(0xfaffffff), (255, 255, 255, 250))

    def test_hash(self):
        salsa = Salsa20(None, None)
        self.assertEqual(salsa.hash([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                         [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                         )
        self.assertEqual(salsa.hash([211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
                                     49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
                                     31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
                                     79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54]),
                         [109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154,
                          29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
                          118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
                          219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202]
                         )
        self.assertEqual(salsa.hash([88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243,
                                     191, 187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37,
                                     86, 16, 179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48,
                                     238, 55, 204, 36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113]),
                         [179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158,
                          26, 110, 170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
                          69, 144, 51, 57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48,
                          27, 111, 114, 114, 118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35]
                         )

    def test_expand(self):
        salsa = Salsa20(None, None)
        k0 = [i for i in range(1, 17)]
        k1 = [200 + i for i in range(1, 17)]
        n = [100 + i for i in range(1, 17)]

        self.assertEqual(salsa.expand(k0, n),
                         [39, 173, 46, 248, 30, 200, 82, 17, 48, 67, 254, 239, 37, 18, 13, 247,
                          241, 200, 61, 144, 10, 55, 50, 185, 6, 47, 246, 253, 143, 86, 187, 225,
                          134, 85, 110, 246, 161, 163, 43, 235, 231, 94, 171, 51, 145, 214, 112, 29,
                          14, 232, 5, 16, 151, 140, 183, 141, 171, 9, 122, 181, 104, 182, 177, 193])

        self.assertEqual(salsa.expand(k0 + k1, n),
                         [69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98,
                          89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126,
                          104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246, 184,
                          177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103, 246, 74])

    def test_encrypt(self):
        key = [random.randint(0, 255) for _ in range(32)]
        nonce = [random.randint(0, 255) for _ in range(8)]
        salsa = Salsa20(key, nonce)
        message = list(range(100))
        cipher = salsa.encrypt(message)
        self.assertEqual(salsa.decrypt(cipher), message)


if __name__ == '__main__':
    unittest.main()
