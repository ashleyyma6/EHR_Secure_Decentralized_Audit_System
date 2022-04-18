import hashlib
from Crypto.Random import get_random_bytes
from client import *
from Crypto.PublicKey import RSA

# hard code add clients
def add_patient(username,pw):
    print()

patient_username = ['alice','bob']

def auth_setup(password):
    # salt size in bytes
    SALT_SIZE = 16
    # number of iterations in the key generation
    NUMBER_OF_ITERATIONS = 20
    
    salt = get_random_bytes(SALT_SIZE)
    pw_salt = password.encode() + salt
    for i in range(NUMBER_OF_ITERATIONS):
        pw_salt = hashlib.sha256(pw_salt).digest()
    return [salt,pw_salt]

def auth_verify(password, auth):
    pw_salt = password.encode() + auth[0]
    # number of iterations in the key generation
    NUMBER_OF_ITERATIONS = 20
    for i in range(NUMBER_OF_ITERATIONS):
        pw_salt = hashlib.sha256(pw_salt).digest()
    return (pw_salt == auth[1])


# auth = auth_setup('password')
# print(auth)
# auth_result = auth_verify('password',auth)
# print(auth_result)


#https://devrescue.com/python-rsa-encrypt-with-public-key/?msclkid=03be053cbedc11ec953a1c5dfa1055de
def gen_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    # use key = RSA.import_key(open('public_key.pem').read())
    return [public_key, private_key] 

# RSA_key_pair = gen_key_pair()
# print(RSA_key_pair)