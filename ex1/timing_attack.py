import naive_rsa
import time
import sys
from random import randrange
from matplotlib import pyplot
import numpy as np
import blessed

#number of bits the modulus
n_bits = 20
#number of samples captured by eve - (encrypted x, time to respond) tuples
num_samples = 64

max_bactracks = 10

# key gen function
def key_gen(n_bits):
    N, e, d, p, q = naive_rsa.GenRSA("1" * (n_bits + 1))
    return (N, e, d, p, q)

# decryptioon oracle for Eve
def decryption_oracle(enc_x, N, d):
    start = time.time()
    #encrypt the message
    x, h, r = naive_rsa.dec(enc_x, N, d)
    res_time = time.time() - start
    #eve eavesdrops the protocol, so she knows those
    return x, res_time, r
    
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

#eve knows N
eve["N"] = alice ["N"]

#Alice knows every parameter of RSA
print("Alice knows: ", alice.keys())

#Evesdropping phase
def gen_message_sets(N, d_i, n):
    #first list is for j == 0, and second for j == 1
    no_extra_set = [[], []]
    extra_set = [[], []]

    #First assume bit j = 0, then j = 1
    for bit in (0, 1):
        while len(no_extra_set[bit]) < n or len(extra_set[bit]) < n:
            enc_x = randrange(0, N)
            
            #simulate decryption up to i 
            m_temp, _, _ = decryption_oracle(enc_x,N, d_i)

            #simulate next decryption step up to the if d_j == 1 part
            m_temp = pow(m_temp, 2, N)

            #simulate decryption up to if d_(j+1) == 1 part 
            #and check if it produces extra reduction
            extra = requires_extra_reduction(m_temp, enc_x, N, d_i, bit)
            if extra:
                extra_set[bit].append(enc_x)
            else:
                no_extra_set[bit].append(enc_x)

    #print(f"Set sizes:\n0 with extra: {len(extra_set[0])}, 0 without extra: {len(no_extra_set[0])},"\
    #      f"1 with extra: {len(extra_set[1])}, 1 without extra {len(no_extra_set[1])}")

    return no_extra_set[:n], extra_set[:n]
  
"""
Return true if encrypted message requires extra reduction for bit i
"""
def requires_extra_reduction(m_temp: int, m: int, N: int, d_i: int, bit: int):
    if bit == 1:
        m_temp = (m_temp * m) % N
    #return true if calculations require extra reduction
    return m_temp * m_temp >= N

def backtrack(d_i):
    return d_i // 2

def fuzzy_equal(mean_1, mean_2):
    return abs(mean_1 - mean_2) < 0.4

def significantly_larger(mean_1, mean_2):
    return (mean_1 - mean_2) > 0.6

def check_key(a, e):
#we have to guess the last bit
    for bit in (0, 1):
        d = e["d"] * 2 + bit

        c_text = randrange(1, e["N"])
        real_x, _, _ = decryption_oracle(c_text, e["N"], a["d"])
        guess_x, _, _ = decryption_oracle(c_text, e["N"], d)
        if real_x == guess_x:
            return (d, True)

    return (e["d"], False)
    


#Eve knows N, and n amount of messages and their response times (enc_x_s, res_time)
print("Eve knows: ", eve.keys())


l = 1
eve["d"] = 1
backtracks = 0
backtracking = False    

term = blessed.Terminal()
print("Starting the crack...")
print(term.cyan(("{0:b}").format(alice["d"])))

with term.location(0, term.height - 1):
    print(term.green("1") + term.gray("_") * (alice["d"].bit_length() - eve["d"].bit_length()))


last_bit = 1
while True:
    with term.location(eve["d"].bit_length(), term.height - 2):
        if backtracking:
            print(term.red("*<") + term.gray("_"), end='')
            backtracking = False
        else:
            print(term.cyan("*"), end='')

    with term.location(0, term.height-1):
        print(term.gray("-") * alice["d"].bit_length(), end='')

    no_extra_r_ciphers, extra_r_ciphers = gen_message_sets(eve["N"], eve["d"], num_samples)

    extra_r_set = [[], []]
    no_extra_r_set = [[], []]

    for bit in (0, 1):
        for c_text in no_extra_r_ciphers[bit]:
            _, res_time, r = decryption_oracle(c_text, alice["N"], alice["d"])
            no_extra_r_set[bit].append(r)
        for c_text in extra_r_ciphers[bit]:
            _, res_time, r = decryption_oracle(c_text, alice["N"], alice["d"])
            extra_r_set[bit].append(r)

    e_r_s_0 = np.array(extra_r_set[0])
    n_e_r_s_0 = np.array(no_extra_r_set[0])
    e_r_s_1 = np.array(extra_r_set[1])
    n_e_r_s_1 = np.array(no_extra_r_set[1])

    if (significantly_larger(e_r_s_0.mean(), n_e_r_s_0.mean()) and fuzzy_equal(e_r_s_1.mean(), n_e_r_s_1.mean())):
        eve["d"] = eve["d"] * 2
        last_bit = 0

    elif (significantly_larger(e_r_s_1.mean(), n_e_r_s_1.mean()) and fuzzy_equal(e_r_s_0.mean(), n_e_r_s_0.mean())):
        eve["d"] = eve["d"] * 2 + 1
        last_bit = 1

    else:
        eve["d"] = backtrack(eve["d"])
        backtracks += 1
        backtracking = True

    with term.location(eve["d"].bit_length()-1, term.height - 2):
        last_bit = ("{0:b}").format(eve["d"])[eve["d"].bit_length() - 1]
        print(term.green(str(last_bit)) if str(last_bit) == ("{0:b}").format(alice["d"])[eve["d"].bit_length() - 1] else term.red(str(last_bit)), end='')

    eve["d"], cracked = check_key(alice, eve)

    if(backtracks >= max_bactracks) or cracked:
        with term.location(eve["d"].bit_length()-1, term.height - 2):
            last_bit = ("{0:b}").format(eve["d"])[eve["d"].bit_length() - 1]
            print(term.green(str(last_bit)) if str(last_bit) == ("{0:b}").format(alice["d"])[eve["d"].bit_length() - 1] else term.red(str(last_bit)), end='')

        print(term.gray("-") * alice["d"].bit_length())
        break

# Key is cracked now, check the results

if (eve["d"] != alice["d"]):
    print(term.red("Couldn't crack the key :( try again!"))
else:
    print(("Cracking complete, the key is:"))
    print(term.blue(("{0:b}").format(eve["d"])))



#print( ("{0:b}" % (n_bits)).format(alice["d"]))
