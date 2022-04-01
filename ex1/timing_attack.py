import naive_rsa
import time
import sys
from random import randrange

#number of bits of the RSA private key
n_bits = 2048
#maximum message value
max_x = sys.maxsize 
#number of messages captured by eve - (encrypted x, time to respond) tuples
num_of_captured_mess = 100

def key_gen(n_bits):
    N, e, d, p, q = naive_rsa.GenRSA("1" * n_bits)
    return (N,e,d,p,q)

def decryption_oracle(enc_x, N, d):
    start = time.time()
    #encrypt the message
    x, _, _ = naive_rsa.dec(enc_x, N, d)
    res_time = time.time() - start
    #eve eavesdrops the protocol, so she knows those
    return res_time
    
print("RSA key is %s bits long, message max size is %s, Eve captured %s messages" % (n_bits, max_x, num_of_captured_mess))
#Alice is the party encrypting the message
alice = {}
#Eve is the attacker, she eavesdrops on the communcation protocol and know x, N, enc_x
eve = {}

#Keygen phase
alice["N"], alice["e"], alice["d"], alice["p"], alice["q"] = key_gen(n_bits)
print("Modulus of the key is %s" % alice["N"])
print("Private key is %s" % alice["d"])

#eve knows N
eve["N"] = alice ["N"]

#Alice knows every parameter of RSA
print("Alice knows: ", alice.keys())


#Evesdropping phase
eve["messages"] = {}
for i in range(num_of_captured_mess):
    #message to be encrypted
    x = randrange(max_x)
    #Encryption
    enc_x, _, _ = naive_rsa.enc(x, alice["N"], alice["e"])

    #Decryption + eavesdropiing
    eve["messages"][enc_x] = decryption_oracle(enc_x, alice["N"], alice["d"])    
    #print("Message: %s, Enc: %s, time to respond: %s" % (x, enc_x, eve["messages"][enc_x]))

#Eve knows N, and n amount of messages and their response times (enc_x, res_time)
print("Eve knows: ", eve.keys())



