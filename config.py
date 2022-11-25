from fastecdsa import keys, curve, point

# number of IOT devices
N = 2

# in curve.P256, y^2 = x^3 + ax + b (mod p)
p = curve.P256.p

# in curve.P256, q is order of base point G
q = curve.P256.q

# number of bytes in q
qL = 32

# delta T (s)
dT = 10
