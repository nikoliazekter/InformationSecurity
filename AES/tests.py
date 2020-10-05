import unittest

from aes import *


class TestHelperFunctions(unittest.TestCase):
    def test_to_blocks_encode(self):
        blocks = list(to_blocks(list(range(100))))
        self.assertEqual(blocks[0], [12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3])

    def test_to_hex(self):
        self.assertEqual(to_hex(np.array([0x19, 0xf4, 0xbe, 0x02], dtype=np.ubyte)), '19f4be02')

    def test_to_word(self):
        self.assertTrue(np.array_equal(to_word('19f4be02'), np.array([0x19, 0xf4, 0xbe, 0x02], dtype=np.ubyte)))


class TestKeyExpansion(unittest.TestCase):
    def test_rot_word(self):
        self.assertTrue(np.array_equal(rot_word(np.array([0x19, 0xf4, 0xbe, 0x02], dtype=np.ubyte)),
                                       np.array([0xf4, 0xbe, 0x02, 0x19], dtype=np.ubyte)))

    def test_sub_word(self):
        self.assertTrue(
            np.array_equal(sub_word(to_word('cf4f3c09')), to_word('8a84eb01')))

    def test_key_expansion(self):
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        w = key_expansion(to_word(key))
        self.assertTrue(to_hex(w[0].T) == '2b7e1516')
        self.assertTrue(to_hex(w[15].T) == '6d7a883b')
        self.assertTrue(to_hex(w[35].T) == '7f8d292f')
        self.assertTrue(to_hex(w[43].T) == 'b6630ca6')


class TestCipher(unittest.TestCase):
    def test_add_round_key(self):
        state = np.array([[0x32, 0x88, 0x31, 0xe0],
                          [0x43, 0x5a, 0x31, 0x37],
                          [0xf6, 0x30, 0x98, 0x07],
                          [0xa8, 0x8d, 0xa2, 0x34]], dtype=np.ubyte)
        round_key = np.array([[0x2b, 0x28, 0xab, 0x09],
                              [0x7e, 0xae, 0xf7, 0xcf],
                              [0x15, 0xd2, 0x15, 0x4f],
                              [0x16, 0xa6, 0x88, 0x3c]], dtype=np.ubyte)
        self.assertTrue(np.array_equal(add_round_key(state, round_key),
                                       np.array([[0x19, 0xa0, 0x9a, 0xe9],
                                                 [0x3d, 0xf4, 0xc6, 0xf8],
                                                 [0xe3, 0xe2, 0x8d, 0x48],
                                                 [0xbe, 0x2b, 0x2a, 0x08]], dtype=np.ubyte)))

    def test_sub_bytes(self):
        state = np.array([[0x19, 0xa0, 0x9a, 0xe9],
                          [0x3d, 0xf4, 0xc6, 0xf8],
                          [0xe3, 0xe2, 0x8d, 0x48],
                          [0xbe, 0x2b, 0x2a, 0x08]], dtype=np.ubyte)
        self.assertTrue(np.array_equal(sub_bytes(state),
                                       np.array([[0xd4, 0xe0, 0xb8, 0x1e],
                                                 [0x27, 0xbf, 0xb4, 0x41],
                                                 [0x11, 0x98, 0x5d, 0x52],
                                                 [0xae, 0xf1, 0xe5, 0x30]], dtype=np.ubyte)))

    def test_shift_rows(self):
        state = np.array([[0xd4, 0xe0, 0xb8, 0x1e],
                          [0x27, 0xbf, 0xb4, 0x41],
                          [0x11, 0x98, 0x5d, 0x52],
                          [0xae, 0xf1, 0xe5, 0x30]], dtype=np.ubyte)
        self.assertTrue(np.array_equal(shift_rows(state),
                                       np.array([[0xd4, 0xe0, 0xb8, 0x1e],
                                                 [0xbf, 0xb4, 0x41, 0x27],
                                                 [0x5d, 0x52, 0x11, 0x98],
                                                 [0x30, 0xae, 0xf1, 0xe5]], dtype=np.ubyte)))

    def test_mix_columns(self):
        state = np.array([[0xc3, 0x1a, 0x49, 0x08],
                          [0x81, 0x49, 0x45, 0x2c],
                          [0xd7, 0x6a, 0x68, 0x0f],
                          [0x7f, 0xd3, 0x5a, 0x9a]], dtype=np.ubyte)
        self.assertTrue(np.array_equal(mix_columns(state),
                                       np.array([[0xad, 0x56, 0x6f, 0xf1],
                                                 [0xc7, 0xe5, 0x21, 0xdb],
                                                 [0x76, 0xe9, 0x32, 0x8f],
                                                 [0xf6, 0xb0, 0x42, 0x14]], dtype=np.ubyte)))

    def test_cipher(self):
        plaintext = '00112233445566778899aabbccddeeff'
        key = '000102030405060708090a0b0c0d0e0f'
        w = key_expansion(to_word(key))
        encrypted = to_hex(cipher(to_word(plaintext), w))
        self.assertEqual(encrypted, '69c4e0d86a7b0430d8cdb78070b4c55a')

    def test_decipher(self):
        encrypted = '69c4e0d86a7b0430d8cdb78070b4c55a'
        key = '000102030405060708090a0b0c0d0e0f'
        w = key_expansion(to_word(key))
        decrypted = to_hex(decipher(to_word(encrypted), w))
        self.assertEqual(decrypted, '00112233445566778899aabbccddeeff')


if __name__ == '__main__':
    unittest.main()
