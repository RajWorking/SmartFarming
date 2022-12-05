from fastecdsa import curve

# in curve.P256, y^2 = x^3 + ax + b (mod p)
p = curve.P256.p

# in curve.P256, q is order of base point G
q = curve.P256.q

a = curve.P256.a

b = curve.P256.b

# number of bytes in q
qL = 32

# delta T (s)
dT = 100000000
