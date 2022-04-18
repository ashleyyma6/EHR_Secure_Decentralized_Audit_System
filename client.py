import hashlib
import random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# salt size in bytes
SALT_SIZE = 16
# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 10

class client():
    def __init__(self, username, pw):
        self.role = 0
        self.ID = random.getrandbits(10) # remember check repeat
        self.username = username # for login
        self.auth = self.auth_setup(pw) #salt(plaintext)，password_hash(hash with salt, do not store pw)
        self.keypair = self.gen_key_pair() 
        self.send_key_hash(self.ID, self.keypair[1])

    # https://stackoverflow.com/questions/6425131/encrypt-decrypt-data-in-python-with-salt?msclkid=e9b69309bed011ec9776e5f1316c9769
    def auth_setup(self,pw):        
        salt = get_random_bytes(SALT_SIZE)
        pw_salt = pw.encode() + salt
        for i in range(NUMBER_OF_ITERATIONS):
            pw_salt = hashlib.sha256(pw_salt).digest()
        return [salt,pw_salt]
    
    #https://devrescue.com/python-rsa-encrypt-with-public-key/?msclkid=03be053cbedc11ec953a1c5dfa1055de
    def gen_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        # use key = RSA.import_key(open('public_key.pem').read())
        return [public_key, private_key] 

    # send this to query process unit
    def prv_key_hash(ID,prv_key):
        prv_salt = prv_key
        for i in range(NUMBER_OF_ITERATIONS):
            prv_salt = hashlib.sha256(prv_salt).digest()
        return [ID,prv_salt]

class patient(client):
    def __init__(self, username,pw):
        super().__init__(username,pw)
        self.role = 3
        self.patientRecord = [] # record structure? only store record ID/hash
        self.patientRecordUsage = [] # record structure? only store record ID/hash
    
    def check_variables(self): #  for test use
        print(self.role)
        print(self.ID)
        print(self.username)
        print(self.auth)

class doctor(client): 
    def __init__(self, username,pw):
        super().__init__(username,pw)
        self.role = 2
        self.actionHistory = [] # record structure? only store record ID/hash

class audit_company(client):
    def __init__(self, username,pw):
        super().__init__(username,pw)
        self.role = 1
        self.actionHistory = [] # record structure? only store record ID/hash

def load_client():
    print()

def load_patient_record():
    print()

# test_patient = patient('alice','password')
# test_patient.check_variables()