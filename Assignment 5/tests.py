import os
import unittest

from elliptic_curve import EllipticCurve
from galois_field import GF
from signature import DigitalSignature


class TestGF(unittest.TestCase):

    def test_mul(self):
        gf = GF(8, 4, 3, 1)
        a = 0x53
        b = 0xCA
        p = gf.mul(a, b)
        self.assertEqual(p, 1)

    def test_pow(self):
        gf = GF()

        def pow_dumb(a, n):
            r = 1
            for _ in range(n):
                r = gf.mul(r, a)
            return r

        a = gf.random()
        for i in range(100):
            self.assertEqual(gf.pow(a, i), pow_dumb(a, i))

    def test_inv(self):
        gf = GF()
        for _ in range(50):
            a = gf.random(minimum=1)
            a_inv = gf.inv(a)
            self.assertEqual(gf.mul(a, a_inv), 1)

    def test_div(self):
        gf = GF()
        for _ in range(50):
            a = gf.random()
            b = gf.random(minimum=1)
            q = gf.div(a, b)
            self.assertEqual(gf.mul(b, q), a)

    def test_solve_quadratic_eq(self):
        gf = GF()

        for _ in range(10):
            u = 0
            z0 = gf.random()
            w0 = gf.square(z0)
            z1, k = gf.solve_quadratic_eq(u, w0)
            self.assertEqual(z0, z1)

        for _ in range(10):
            u = gf.random(minimum=1)
            z0 = gf.random()
            w0 = gf.add(gf.square(z0), gf.mul(u, z0))
            z1, k = gf.solve_quadratic_eq(u, w0)
            w1 = gf.add(gf.square(z1), gf.mul(u, z1))
            self.assertEqual(w0, w1)


class TestEllipticCurve(unittest.TestCase):

    def test_generate_point(self):
        ec = EllipticCurve(GF())
        for _ in range(10):
            point = ec.generate_point()
            self.assertTrue(ec.on_curve(point))

    def test_add_point(self):
        ec = EllipticCurve(GF())
        for _ in range(10):
            p = ec.generate_point()
            q = ec.generate_point()
            r = ec.add_points(p, q)
            self.assertTrue(ec.on_curve(p))
            self.assertTrue(ec.on_curve(q))
            self.assertTrue(ec.on_curve(r))
            p_neg = ec.negate_point(p)
            q_neg = ec.negate_point(q)
            self.assertEqual(ec.add_points(r, p_neg), q)
            self.assertEqual(ec.add_points(r, q_neg), p)

    def test_multiple(self):
        ec = EllipticCurve(GF())

        def multiple_dumb(point, n):
            q = ec.infinity
            for _ in range(n):
                q = ec.add_points(q, point)
            return q

        p = ec.generate_point()
        for i in range(10):
            self.assertEqual(multiple_dumb(p, i),
                             ec.multiple(p, i))


class TestDigitalSignature(unittest.TestCase):

    def test_pair_transform(self):
        ec = EllipticCurve(GF())
        base_point = ec.base_point()
        ds = DigitalSignature(ec, base_point)
        for _ in range(10):
            r0 = ds.random_int()
            s0 = ds.random_int()
            signature = ds.to_signature(r0, s0)
            r1, s1 = ds.to_pair(signature)
            self.assertEqual(r0, r1)
            self.assertEqual(s0, s1)

    def test_sign(self):
        ec = EllipticCurve(GF())
        base_point = ec.base_point()
        ds = DigitalSignature(ec, base_point)
        d = ds.gen_private_key()
        Q = ds.gen_public_key(d)
        message = os.urandom(16)
        message, signature = ds.sign(message, d)
        self.assertTrue(ds.verify(message, signature, Q))


class TestExample(unittest.TestCase):

    def test(self):
        gf = GF(163, 7, 6, 3)
        ec = EllipticCurve(gf, A=1,
                           B=0x5FF6108462A2DC8210AB403925E638A19C1455D21,
                           n=0x400000000000000000002BEC12BE2262D39BCF14D)
        base_point = (0x72D867F93A93AC27DF9FF01AFFE74885C8C540420,
                      0x0224A9C3947852B97C5599D5F4AB81122ADC3FD9B)
        ds = DigitalSignature(ec, base_point)
        d = 0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E
        Q = ds.gen_public_key(d)
        self.assertEqual(Q, (0x057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA,
                             0x3E85444324BCF06AD85ABF6AD7B5F34770532B9AA))
        h = 0x09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF & gf.mask
        self.assertEqual(h, 0x03A2EB95B7180166DDF73532EEB76EDAEF52247FF)
        e = 0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6
        f_e = ec.multiple(ds.base_point, e)[0]
        self.assertEqual(f_e, 0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C)
        r = gf.mul(h, f_e) & ds.mask
        self.assertEqual(r, 0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7)
        s = (e + d * r) % ec.n
        self.assertEqual(s, 0x2100D86957331832B8E8C230F5BD6A332B3615ACA)
        D = ds.to_signature(r, s)
        self.assertEqual(D,
                         0x000000000000000000000002100D86957331832B8E8C230F5BD6A332B3615ACA00000000000000000000000274EA2C0CAA014A0D80A424F59ADE7A93068D08A7)
        r, s = ds.to_pair(D)
        self.assertEqual(r, 0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7)
        self.assertEqual(s, 0x2100D86957331832B8E8C230F5BD6A332B3615ACA)
        x, y = ec.add_points(ec.multiple(ds.base_point, s),
                             ec.multiple(Q, r))
        self.assertEqual(x, 0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C)
        self.assertEqual(y, 0x5310AE5E560464A95DC80286F17EB762EC544B15B)
        r2 = gf.mul(h, x)
        self.assertEqual(r2, 0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7)


if __name__ == '__main__':
    unittest.main()
