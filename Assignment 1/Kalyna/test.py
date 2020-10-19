import unittest

from kalyna import *


class TestCipherDecipher(unittest.TestCase):
    def test_cipher_decipher(self):
        key22 = to_words('000102030405060708090A0B0C0D0E0F')
        key24 = to_words('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
        key88 = to_words(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')
        plaintext22 = to_words('101112131415161718191A1B1C1D1E1F')
        plaintext24 = to_words('202122232425262728292A2B2C2D2E2F')
        plaintext88 = to_words(
            '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F')

        ctx = init_context(128, 128)
        kalyna_key_expand(ctx, key22)
        ciphertext = kalyna_encipher(ctx, plaintext22)
        deciphered = kalyna_decipher(ctx, ciphertext)
        self.assertEqual(to_hex(deciphered), to_hex(plaintext22))

        ctx = init_context(128, 256)
        kalyna_key_expand(ctx, key24)
        ciphertext = kalyna_encipher(ctx, plaintext24)
        deciphered = kalyna_decipher(ctx, ciphertext)
        self.assertEqual(to_hex(deciphered), to_hex(plaintext24))

        ctx = init_context(512, 512)
        kalyna_key_expand(ctx, key88)
        ciphertext = kalyna_encipher(ctx, plaintext88)
        deciphered = kalyna_decipher(ctx, ciphertext)
        self.assertEqual(to_hex(deciphered), to_hex(plaintext88))


if __name__ == '__main__':
    unittest.main()
