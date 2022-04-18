import sys
import hashlib
from Crypto.Random import get_random_bytes
from client import *

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
    print(password.encode(), type(password.encode()))
    print(auth[0], type(auth[0]))
    pw_salt = password.encode() + auth[0]
    # number of iterations in the key generation
    NUMBER_OF_ITERATIONS = 20
    for i in range(NUMBER_OF_ITERATIONS):
        pw_salt = hashlib.sha256(pw_salt).digest()
    return (pw_salt == auth[1])

def login_verify(username,pw):
    if username in patient_username:
        if auth_verify(pw,alice_auth):
            return True
        else:
            return False
    else:
        return False

def main():
    if(len(sys.argv)>1):
        user_id = 'alice'# input("Enter user id: ")
        # check user_id in the db
        pw = 'password'# input("Enter password: ")
        # check pw hash
        verify = auth_verify(user_id,pw)

patient_username = ['alice','bob']
alice_auth = auth_setup('password')
print(alice_auth)
main()