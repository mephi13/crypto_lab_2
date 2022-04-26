import rsa_blinded
import time
import sys
from random import randrange
import numpy as np
import blessed

#number of bits the modulus
n_bits = 20
#number of samples captured by eve - (encrypted x, time to respond) tuples
num_samples = 32
#maximum amount of backtracks
max_bactracks = 10

# key gen function
def key_gen(n_bits):
    N, e, d, p, q = rsa_blinded.GenRSA("1" * (n_bits + 1))
    return (N, e, d, p, q)

# decryptioon oracle for Eve
def decryption_oracle(enc_x, N, d, e):
    start = time.time()

    #decrypt the message
    x, h, r = rsa_blinded.dec(enc_x, N, d, e)
    res_time = time.time() - start
    #eve eavesdrops the protocol, so she knows those
    return x, res_time, r

def gen_message_sets(N, d_i, n, e):
    #first list is for j == 0, and second for j == 1
    no_extra_set = [[], []]
    extra_set = [[], []]

    #First assume bit j = 0, then j = 1
    for bit in (0, 1):
        while len(no_extra_set[bit]) < n or len(extra_set[bit]) < n:
            enc_x = randrange(0, N)
            
            #simulate decryption up to i 
            m_temp, _, _ = rsa_blinded.dec(enc_x,N, d_i, e)

            #simulate next decryption step up to the if d_j == 1 part
            m_temp = pow(m_temp, 2, N)

            #simulate decryption up to if d_(j+1) == 1 part 
            #and check if it produces extra reduction
            extra = requires_extra_reduction(m_temp, enc_x, N, d_i, bit)
            if extra:
                extra_set[bit].append(enc_x)
            else:
                no_extra_set[bit].append(enc_x)

    return no_extra_set[:n], extra_set[:n]
  
def requires_extra_reduction(m_temp: int, m: int, N: int, d_i: int, bit: int):
    """
    Return true if encrypted message requires extra reduction for bit i
    """
    if bit == 1:
        m_temp = (m_temp * m) % N
    #return true if calculations require extra reduction
    return m_temp * m_temp >= N

def backtrack(d_i):
    return d_i // 2 if d_i != 1 else d_i

def fuzzy_equal(mean_1, mean_2):
    return abs(mean_1 - mean_2) < 0.3

def significantly_larger(mean_1, mean_2):
    return (mean_1 - mean_2) > 0.5

def check_key(alice, eve):
#we have to guess the last bit
    for bit in (0, 1):
        d = eve["d"] * 2 + bit

        c_text = randrange(1, eve["N"])
        real_x, _, _ = rsa_blinded.dec(c_text, alice["N"], alice["d"], alice["e"])
        guess_x, _, _ = rsa_blinded.dec(c_text, eve["N"], d, eve["e"])
        if real_x == guess_x:
            return (d, True)

    return (eve["d"], False)
    
if __name__== "__main__":
    print("RSA modulus is %s bits long, Eve has %s samples" % (n_bits, num_samples))
    #Alice is the party encrypting the message
    alice = {}
    #Eve is the attacker, she eavesdrops on the communcation protocol and know x, N, enc_x_s
    eve = {}

    #Keygen phase
    alice["N"], alice["e"], alice["d"], alice["p"], alice["q"] = key_gen(n_bits)
    print("Modulus of the key is %s" % alice["N"])
    print("Private key is %s" % alice["d"])
    print( ("{0:b}").format(alice["d"]))

    # test if decryption with blind input works
    mes = 123
    enc, _, _ = rsa_blinded.enc(mes, alice["N"], alice["e"])
    dec, _, _ = decryption_oracle(enc, alice["N"], alice["d"], alice["e"])
    print(f"message = {mes}, enc mex = {enc}, dec mes = {dec}")

    #eve knows N, e
    eve["N"] = alice ["N"]
    eve["e"] = alice ["e"]
    print("Eve knows: ", eve.keys())

    #Alice knows every parameter of RSA
    print("Alice knows: ", alice.keys())

    l = 1
    eve["d"] = 1
    backtracks = 0
    backtracking = False    

    term = blessed.Terminal()
    print("Starting the crack...")
    print(term.cyan(("{0:b}").format(alice["d"])))
    print(term.green("1") + term.gray("_") * (alice["d"].bit_length() - eve["d"].bit_length()))
    print(term.gray("-") * alice["d"].bit_length())
    print(term.move_up(2) + term.move_right, end="")

    last_bit = 1
    while True:
        # just printing stuff
        if backtracking:
            print(term.move_left(2), end="")
            with term.location():
                print(term.red("*<"))
            print(term.right, end="")
            backtracking = False
        else:
            #print(term.move_right, end="")
            with term.location():
                print(term.cyan("*"), end="")
            

        # generate sets of ciphertexts:
        # 1st set: We assume that the next bit of private key is equal to 0
        #   and we search for ciphertexts that generate extra reduction
        # 2nd set: We assume that the next bit of private key is equal to 0
        #   and we search for ciphertexts that do not generate extra reduction
        # 3rd set: We assume that the next bit of private key is equal to 1
        #   and we search for ciphertexts that generate extra reduction
        # 4th set: We assume that the next bit of private key is equal to 1
        #   and we search for ciphertexts that do not generate extra reduction
        no_extra_r_ciphers, extra_r_ciphers = gen_message_sets(eve["N"], eve["d"], num_samples, eve["e"])
        extra_r_set = [[], []]
        no_extra_r_set = [[], []]

        # ask decryption oracle to dec
        for bit in (0, 1):
            for c_text in no_extra_r_ciphers[bit]:
                _, res_time, r = decryption_oracle(c_text, alice["N"], alice["d"], alice["e"])
                no_extra_r_set[bit].append(r)
            for c_text in extra_r_ciphers[bit]:
                _, res_time, r = decryption_oracle(c_text, alice["N"], alice["d"], alice["e"])
                extra_r_set[bit].append(r)

        # sets generated on premise that the next bit is equal to 0
        extra_r_0bit = np.array(extra_r_set[0])
        no_extra_r_0bit = np.array(no_extra_r_set[0])

        # sets generated on premise that the next bit is equal to 1
        extra_r_1bit = np.array(extra_r_set[1])
        no_extra_r_1bit = np.array(no_extra_r_set[1])

        # check if there's a significant difference in time (reductions) between extra reduction set and 
        # no extra reduction set for assumed bit 0 and at the same time that reductions for sets with assumed bit 1
        # are roughly the same
        if (significantly_larger(extra_r_0bit.mean(), no_extra_r_0bit.mean()) and fuzzy_equal(extra_r_1bit.mean(), no_extra_r_1bit.mean())):
            eve["d"] = eve["d"] * 2
            last_bit = 0
        # check if there's a significant difference in time (reductions) between extra reduction set and 
        # no extra reduction set for assumed bit 1 and at the same time that reductions for sets with assumed bit 0
        # are roughly the same
        elif (significantly_larger(extra_r_1bit.mean(), no_extra_r_1bit.mean()) and fuzzy_equal(extra_r_0bit.mean(), no_extra_r_0bit.mean())):
            eve["d"] = eve["d"] * 2 + 1
            last_bit = 1
        # if for both assumed bits there is a significant difference between extra reduction and no extra reduction sets
        # or for both assumed bits the reductions in sets are roughly equal, we need to backtrack because
        # there's was probably a wrongly set bit before
        elif eve["d"] != 1:
            eve["d"] = backtrack(eve["d"])
            
            backtracks += 1
            backtracking = True
        else:
            backtracks += 1
            print(term.move_left, end="")

        # just printing stuff
        last_bit = ("{0:b}").format(eve["d"])[eve["d"].bit_length() - 1]
        print(term.green(str(last_bit)) if str(last_bit) == ("{0:b}").format(alice["d"])[eve["d"].bit_length() - 1] else term.red(str(last_bit)), end="")

        # check if the key has been cracked, because we don't know how long is the key
        eve["d"], cracked = check_key(alice, eve)

        # if the key has been cracked or maximum amount of backtracks has been reached, leave the loop
        if(backtracks >= max_bactracks) or cracked:
            last_bit = ("{0:b}").format(eve["d"])[eve["d"].bit_length() - 1]
            print(term.green(str(last_bit)) if str(last_bit) == ("{0:b}").format(alice["d"])[eve["d"].bit_length() - 1] else term.red(str(last_bit)))

            break

    # Key is cracked now, check the results

    if (eve["d"] != alice["d"]):
        print(term.red("Couldn't crack the key :( try again!"))
    else:
        print(("Cracking complete, the key is:"))
        print(term.blue(("{0:b}").format(eve["d"])))
