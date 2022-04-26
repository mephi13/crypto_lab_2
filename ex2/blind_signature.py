from collections import namedtuple
import random
import math
from dataclasses import dataclass
import naive_rsa
# We will be using RSA to sign messages

rsa = namedtuple("rsa", "N e d p q")
blind_rsa = namedtuple("blind_rsa", "N e r")

class blind_signature:
    """Blind signature cryptosystem."""

    @dataclass
    class signer:
        N: int
        e: int
        d: int
        p: int 
        q: int
        def __init__(self, modulus_bit_length=20):
            #set RSA params
            self.N, self.e, self.d, self.p, self.q = rsa(*naive_rsa.GenRSA(modulus_bit_length*"1"))

        def s(self, x):
            """Inverse of signing function s' publicly known, such that s(s_prim(x)) == x."""
            m, _, _ = naive_rsa.enc(x, self.N, self.e)
            return m

        def s_prim(self, m):
            """Signing function s' known only to the signer."""
            x, _, _ = naive_rsa.dec(m, self.N, self.d)
            return x

        def verify(self, message, signature):
            """Inverse of signing function s' publicly known, such that s(s_prim(x)) == x."""
            return self.s(signature) == message

    @dataclass
    class provider:
        N: int
        e: int
        r: int
        def __init__(self, N, e):
            
            # calculate r, which will blind the input
            r = self.gen_r(N)
            
            # set provider params
            self.N = N
            self.e = e
            self.r = r

        def gen_r(self, N):
            r = random.randrange(2, N)

            # generate a random r such that gcd(r,N) == 1
            while math.gcd(r, N) != 1:
                r = random.randrange(2, N)
                
            return r

        def c(self, x):
            """Commuting function c known only the provider."""
            blinding_factor = pow(self.r, self.e, self.N)
            c = (x * blinding_factor) % self.N
            return c

        def c_prim(self, m):
            """Inverse of cummuting function c known only the provider such that c_prim(s_prim(c(x))) == s_prim(x)."""
            x = (m * pow(self.r, -1, self.N)) % self.N
            return x


if __name__ == "__main__":
    # create signer and provider instances
    mes_str = "hello"
    N_bits = 20

    signer = blind_signature.signer(N_bits)
    provider = blind_signature.provider(signer.N, signer.e)

    print(f"message to be signed = {mes_str}")
    message = hash(mes_str) % signer.N
    print(f"message hash = {message}")

    print(signer)
    print(provider)

    # provider chooses x at random and forms c(x)
    c_x = provider.c(message)
    print(f"c_x = {c_x}")

    # Signer signs c(x) by applying s' and return the signed matter s'(c(s)) to the provider
    s_prim_c_x = signer.s_prim(c_x)
    print(f"s_prim_c_x = {s_prim_c_x}")

    # Provider strips signed matter by application of c', yielding c'(s'(c(x))) = s'(x)
    s_prim_x = provider.c_prim(s_prim_c_x)
    print(f"s_prim_x = {s_prim_x}")

    # Anyone can check that the stripped matter s'(x) was formed by the signer
    # by checking the signature against the publicly known function s
    decrypted_message = signer.s(s_prim_x)

    verify =  signer.verify(message, s_prim_x)

    print(f"Decrypted message hash = {decrypted_message}, real message hash = {message}")
    print("Signature " + "verified!" if message == decrypted_message else "not verified!")

