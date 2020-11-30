class EllipticCurve:

    def __init__(self, gf, A=1,
                 B=0x4A6E0856526436F2F88DD07A341E32D04184572BEB710,
                 n=0x3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF):
        self.gf = gf
        self.A = A
        self.B = B
        self.n = n
        self.infinity = (0, 0)

    def on_curve(self, point):
        if point == self.infinity:
            return True
        x, y = point
        left = self.gf.add(self.gf.square(y),
                           self.gf.mul(x, y))
        right = self.gf.add(self.gf.add(
            self.gf.pow(x, 3),
            self.gf.mul(self.A,
                        self.gf.square(x))),
            self.B)
        return left == right

    def generate_point(self):
        while True:
            u = self.gf.random()
            w = self.gf.add(self.gf.add(
                self.gf.pow(u, 3),
                self.gf.mul(self.A,
                            self.gf.square(u))),
                self.B)
            z, k = self.gf.solve_quadratic_eq(u, w)
            if k > 0:
                return u, z

    def negate_point(self, point):
        x, y = point
        return x, self.gf.add(x, y)

    def add_points(self, point1, point2):
        if point1 == self.infinity:
            return point2
        if point2 == self.infinity:
            return point1
        if point1 == point2:
            return self.double_point(point1)
        if point2 == self.negate_point(point1):
            return self.infinity

        x1, y1 = point1
        x2, y2 = point2
        sum_x = self.gf.add(x1, x2)
        mu = self.gf.div(self.gf.add(y1, y2),
                         sum_x)
        x3 = self.gf.add(self.gf.add(self.gf.add(
            self.gf.square(mu),
            mu),
            sum_x),
            self.A)
        y3 = self.gf.add(self.gf.add(
            self.gf.mul(mu,
                        self.gf.add(x1, x3)),
            x3),
            y1)
        return x3, y3

    def double_point(self, point):
        x, y = point
        mu = self.gf.add(x, self.gf.div(y, x))
        x2 = self.gf.add(self.gf.add(
            self.gf.square(mu),
            mu),
            self.A)
        y2 = self.gf.add(
            self.gf.square(x),
            self.gf.mul(
                self.gf.add(mu, 1),
                x2))
        return x2, y2

    def multiple(self, point, n):
        q = self.infinity
        while n > 0:
            if n & 1 == 1:
                q = self.add_points(q, point)
            point = self.double_point(point)
            n = n >> 1
        return q

    def base_point(self):
        while True:
            p = self.generate_point()
            r = self.multiple(p, self.n)
            if r == self.infinity:
                return p
