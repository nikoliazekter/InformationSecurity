import os
import unittest

import rsa
import rsa_oaep
from helpers import miller_rabin


class TestHelpers(unittest.TestCase):
    def test_miller_rabin_small(self):
        k = 40
        self.assertFalse(miller_rabin(0, k))
        self.assertFalse(miller_rabin(1, k))
        self.assertTrue(miller_rabin(2, k))
        self.assertTrue(miller_rabin(3, k))
        self.assertTrue(miller_rabin(5, k))
        self.assertTrue(miller_rabin(7, k))
        self.assertFalse(miller_rabin(9, k))
        self.assertFalse(miller_rabin(49, k))

    def test_miller_rabin_big(self):
        k = 40
        a = 5988382547900011059982773127027433035392095026839118950463435933621301606863651092678197998843867907
        self.assertTrue(miller_rabin(a, k))
        a = 2680634290893797710985010252260954133644675058169590731281722249639706725073684562150425301849258941
        self.assertTrue(miller_rabin(a, k))
        a = 9888887073510615904985439384337303309438495146692887907705741392812468820404272631972367114291185143
        self.assertTrue(miller_rabin(a, k))
        a = 1353924511762547701077709451863968454502925180139390412678176225163334241341193339501344071526101503
        self.assertTrue(miller_rabin(a, k))
        a = 5318778720949638449818091794022277586062360337394831816824241140001040486130417725006592935770367143
        self.assertTrue(miller_rabin(a, k))

        a = 5988382547900011059982773127027433035392095026839118950463435933621301606863651092678197998843867907
        b = 6676066668704114317437996979438473867662389657659641149291788326199361365713977263095493680135216599
        c = a * b
        self.assertFalse(miller_rabin(c, k))
        a = 2207082965665557636252750227134074819491951548456613283764767087931929449670971559903211765961378691
        b = 8124371620073265128727753686748006988645176153112796276844628570402734281829055972869291629376509659
        c = a * b
        self.assertFalse(miller_rabin(c, k))
        a = 1071927702795395921576199524971807524039260666431303991423118634017080470044343586788715962117388249
        b = 9247933067202004153436078294275831276303660758274985362842462704307485346851085461499535328631108383
        c = a * b
        self.assertFalse(miller_rabin(c, k))
        a = 2161845910344298123517546615803440735782099941912918026967282239275006383393824929606400486216221767
        b = 1306951321047347955264480153672460054495875830058918031941395310832155658486614003563005975572348503
        c = a * b
        self.assertFalse(miller_rabin(c, k))
        a = 6318160355069116556838992957997171785465527132041540365420770985183257715841077693320681695853902437
        b = 6837144848827524569759428098884117242074216522967094829401958847127857876553068680684555480235131283
        c = a * b
        self.assertFalse(miller_rabin(c, k))


class TestRSA(unittest.TestCase):
    def test_rsa128(self):
        for byte_length in [0, 10, 20, 30]:
            public_key, private_key = rsa.new_key_pair(128)
            plaintext = os.urandom(byte_length)
            ciphertext = rsa.encrypt(plaintext, public_key)
            new_plaintext = rsa.decrypt(ciphertext, private_key)
            self.assertEqual(plaintext, new_plaintext)

    def test_rsa512(self):
        for byte_length in [0, 25, 50, 75, 100, 125]:
            public_key, private_key = rsa.new_key_pair(512)
            plaintext = os.urandom(byte_length)
            ciphertext = rsa.encrypt(plaintext, public_key)
            new_plaintext = rsa.decrypt(ciphertext, private_key)
            self.assertEqual(plaintext, new_plaintext)


class TestRSA_OAEP(unittest.TestCase):
    def test_rsa_oaep512(self):
        for byte_length in [0, 10, 20, 30]:
            public_key, private_key = rsa_oaep.new_key_pair(512)
            plaintext = os.urandom(byte_length)
            ciphertext = rsa_oaep.encrypt(plaintext, public_key, b'hello')
            new_plaintext = rsa_oaep.decrypt(ciphertext, private_key, b'hello')
            self.assertEqual(plaintext, new_plaintext)


if __name__ == '__main__':
    unittest.main()
