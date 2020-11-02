import random
import unittest

from kupyna import Kupyna
from sha256 import SHA256


class TestSHA256(unittest.TestCase):
    def test_hash(self):
        message = 'abc'
        message = ''.join([hex(ord(c))[2:].zfill(2) for c in message])
        sha = SHA256()
        hash = sha.hash(message)
        expected_hash = 0xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
        self.assertEqual(hash, expected_hash)

        message = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        message = ''.join([hex(ord(c))[2:].zfill(2) for c in message])
        sha = SHA256()
        hash = sha.hash(message)
        expected_hash = 0x248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1
        self.assertEqual(hash, expected_hash)


class TestKupyna(unittest.TestCase):
    def test_state_transforms(self):
        N = 10
        kupyna = Kupyna(256)
        for i in range(N):
            word = random.randint(0, 2 ** 64 - 1)
            state = kupyna.word_to_state(word)
            new_word = kupyna.state_to_word(state)
            self.assertEqual(word, new_word)

        kupyna = Kupyna(512)
        for i in range(N):
            word = random.randint(0, 2 ** 64 - 1)
            state = kupyna.word_to_state(word)
            new_word = kupyna.state_to_word(state)
            self.assertEqual(word, new_word)

    def test_xor_state_value(self):
        kupyna = Kupyna(256)

        word = int('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                   '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.xor_state_value(state, 0)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('000102030405060718090A0B0C0D0E0F301112131415161728191A1B1C1D1E1F'
                            '602122232425262778292A2B2C2D2E2F503132333435363748393A3B3C3D3E3F', 16)
        self.assertEqual(new_word, expected_word)

        word = int('4DA74F33C3485F0C9560F6400144488E65E3C69CD3B296FBA3F3430A2E154FE2'
                   'E4B32BB503DFED48860D18AEBC3E135CCF4853EB8CAFB6B622BE8F7562D01010', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.xor_state_value(state, 1)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('4CA74F33C3485F0C8460F6400144488E44E3C69CD3B296FB92F3430A2E154FE2'
                            'A5B32BB503DFED48D70D18AEBC3E135CAE4853EB8CAFB6B653BE8F7562D01010', 16)
        self.assertEqual(new_word, expected_word)

    def test_sub_bytes(self):
        kupyna = Kupyna(256)
        word = int('000102030405060718090A0B0C0D0E0F301112131415161728191A1B1C1D1E1F'
                   '602122232425262778292A2B2C2D2E2F503132333435363748393A3B3C3D3E3F', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.sub_bytes(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('A8BB9A4D6BCB452A793ADFB31790511F92152B3DC91CBB831F5C71D56F5716BD'
                            '34F6C002B4F4AD118E0F7A5E496DD1662E26C445D15DB7949C140E1A5810B2DF', 16)
        self.assertEqual(new_word, expected_word)

        word = int('4CA74F33C3485F0C8460F6400144488E44E3C69CD3B296FB92F3430A2E154FE2'
                   'A5B32BB503DFED48D70D18AEBC3E135CAE4853EB8CAFB6B653BE8F7562D01010', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.sub_bytes(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('8FA035458CD148545CE754B543BD922742D019FB0D8037C969F00326931C356B'
                            '681EC85006AD06E91A90624294D8C218A2D19EAD3FF90D015A2429A6FC504A22', 16)
        self.assertEqual(new_word, expected_word)

    def test_shift_bytes(self):
        kupyna = Kupyna(256)
        word = int('A8BB9A4D6BCB452A793ADFB31790511F92152B3DC91CBB831F5C71D56F5716BD'
                   '34F6C002B4F4AD118E0F7A5E496DD1662E26C445D15DB7949C140E1A5810B2DF', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.shift_bytes(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('A814C45EB457BB1F79BB0E4549F41683923A9A1AD16DADBD1F15DF4D585DD111'
                            '345C2BB36B10B7668EF6713D17CBB2942E0FC0D5C99045DF9C267A026F1C512A', 16)
        self.assertEqual(new_word, expected_word)

        word = int('8FA035458CD148545CE754B543BD922742D019FB0D8037C969F00326931C356B'
                   '681EC85006AD06E91A90624294D8C218A2D19EAD3FF90D015A2429A6FC504A22', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.shift_bytes(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('8F249E42061C37275CA029AD94AD35C942E735A63FD8066B69D05445FCF9C2E9'
                            '68F019B58C500D181A1E03FB43D14A01A290C8260DBD48225AD1625093809254', 16)
        self.assertEqual(new_word, expected_word)

    def test_mix_columns(self):
        kupyna = Kupyna(256)
        word = int('A814C45EB457BB1F79BB0E4549F41683923A9A1AD16DADBD1F15DF4D585DD111'
                   '345C2BB36B10B7668EF6713D17CBB2942E0FC0D5C99045DF9C267A026F1C512A', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.mix_columns(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('4DA74F33C3485F0C9560F6400144488E65E3C69CD3B296FBA3F3430A2E154FE2'
                            'E4B32BB503DFED48860D18AEBC3E135CCF4853EB8CAFB6B622BE8F7562D01010', 16)
        self.assertEqual(new_word, expected_word)

        word = int('8F249E42061C37275CA029AD94AD35C942E735A63FD8066B69D05445FCF9C2E9'
                   '68F019B58C500D181A1E03FB43D14A01A290C8260DBD48225AD1625093809254', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.mix_columns(state)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('544AB381EA8ACA3449A9DD1F7D9FB4484E6AB7B5F93A61B18D05B4760C023FB9'
                            'FA5FA01A21EEBF29E1662942BAB4A85A779BEF260345DD8873D6AE28FF1D16FC', 16)
        self.assertEqual(new_word, expected_word)

    def test_T_xor(self):
        kupyna = Kupyna(256)
        word = int('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                   '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F', 16)
        new_word = kupyna.T_xor(word)
        expected_word = int('20A066016C8DAA5AA2ACA450D21F2796FBDC2E0CC452AF0AAF67E27A0755CB32'
                            '718C2C7909201D3E7A3F256234C80B70D51AE3936DB26CF56E1F1BA8A0A7E1C0', 16)
        self.assertEqual(new_word, expected_word)

    def test_add_state_value(self):
        kupyna = Kupyna(256)

        word = int('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                   '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.add_state_value(state, 0)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('F3F1F2F3F4F5F677FBF9FAFBFCFDFE6F03020304050607680B0A0B0C0D0E0F60'
                            '13121314151617581B1A1B1C1D1E1F5023222324252627482B2A2B2C2D2E2F40', 16)
        self.assertEqual(new_word, expected_word)

        word = int('613A348E2E0AD6C6C167BD5CBF7C35CD3F0C39640DF28FEBCCDDC66B1CADBAD6'
                   '0A5B588D3DAE1DEFCD3F0FACF8109B10D1F623F7957C9A96B5F63A9798562BFC', 16)
        state = kupyna.word_to_state(word)
        new_state = kupyna.add_state_value(state, 5)
        new_word = kupyna.state_to_word(new_state)
        expected_word = int('542B257F1FFBC63CB458AE4DB06D263332FD2955FEE28041BFCEB75C0D9EAB1C'
                            'FD4B497E2E9F0E25C030009DE9018C36C4E714E8866D8BACA8E72B8889471C02', 16)
        self.assertEqual(new_word, expected_word)

    def test_T_add(self):
        kupyna = Kupyna(256)
        word = int('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                   '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F', 16)
        new_word = kupyna.T_add(word)
        expected_word = int('2D6F3A8E12F162AEC3F76E0402575068671824EF72FEA1CD7D71FD4D8E6A27A1'
                            '0C2BA7EBF31C277F91DD384731025A8DF3013049279CF47251B2434F2632F00A', 16)
        self.assertEqual(new_word, expected_word)

    def test_hash(self):
        kupyna = Kupyna(256)
        hash = kupyna.hash('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                           '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')
        expected_hash = int('08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875', 16)
        self.assertEqual(hash, expected_hash)

        hash = kupyna.hash('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                           '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F'
                           '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F'
                           '606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F')
        expected_hash = int('0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882', 16)
        self.assertEqual(hash, expected_hash)

        hash = kupyna.hash('')
        expected_hash = int('CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6', 16)
        self.assertEqual(hash, expected_hash)

        kupyna = Kupyna(512)
        hash = kupyna.hash('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
                           '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')
        expected_hash = int('3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B'
                            '3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A', 16)
        self.assertEqual(hash, expected_hash)


if __name__ == '__main__':
    unittest.main()
