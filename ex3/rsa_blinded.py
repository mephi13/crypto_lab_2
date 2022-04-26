from sympy import randprime, mod_inverse
import math, random

def GenModulus(w):
    n = len(w) // 2
    p = randprime(2 ** n, 2 ** (n+1))
    q = randprime(2 ** n, 2 ** (n+1))
    N = p * q
    return N, p, q

def GenRSA(w):
    N, p, q = GenModulus(w)
    m = (p-1) * (q-1)
    e = 2 ** 16 + 1
    d = mod_inverse(e, m)
    return N, e, d, p, q

def gen_r(N):
    r = random.randrange(2, N)

    # generate a random r such that gcd(r,N) == 1
    while math.gcd(r, N) != 1:
        r = random.randrange(2, N)
        
    return r

def enc(x, N, e):
    return fast_pow(x, N, e) #x ** e % N

def dec(c, N, d, e):
    # modified to work on blind input

    r = gen_r(N)
    blinding_factor, hf, rbf = fast_pow(r, N, e)

    # first we apply c function, i.e. c * r^e mod N
    c_blinded = (c * blinding_factor) % N

    # then we decrypt aka c^d mod N
    c_blinded_dec, hd, rd = fast_pow(c_blinded, N, d)

    # then we unblind, i.e. x * r^-1 mod N
    r_inv = pow(r, -1, N)
    x = (c_blinded_dec * r_inv) % N

    reductions = rbf  
    h = hf
    return  x, h, reductions

def fast_pow(c, N, d):
    d_bin = "{0:b}".format(d)
    d_len = len(d_bin)
    reductions = 0
    h = 0
    x = c
    for j in range(1, d_len):
        x, r = mod_reduce(x ** 2, N)
        reductions = reductions + r
        if d_bin[j] == "1":
            x, r = mod_reduce(x * c, N)
            reductions = reductions + r
            h = h + 1
    return x, h, reductions

def mod_reduce(a, b):
    reductions = 0
    if a >= b:
        a = a % b
        reductions = 1
    return a, reductions
