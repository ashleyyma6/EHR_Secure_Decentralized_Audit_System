import hashlib
import random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json

# salt size in bytes
SALT_SIZE = 16
# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 5

'''
byte to int
int.from_bytes(byte_val, "big")

int to byte
int_val.to_bytes(length, byteorder)

'''

class client():
    def __init__(self):
        self.role = None
        self.ID = None
        self.username = None
        self.auth = None
        self.keypair = None
        self.prvKey_hash = None

    def setup_new_client(self, username, pw):
        self.role = 0
        self.ID = random.getrandbits(10) # remember check repeat
        self.username = username # for login
        self.auth = self.auth_setup(pw) # salt(plaintext)，password_hash(hash with salt, do not store pw)
        self.keypair = self.gen_key_pair() 
        self.prvKey_hash = self.prv_key_hash(self.keypair[1])
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash):
        self.role = role #int
        self.ID = ID #int
        self.username = username #str
        self.auth = auth # [int, int]
        self.keypair = keypair # [str, str]
        self.prvKey_hash = prvKey_hash # int

    # https://stackoverflow.com/questions/6425131/encrypt-decrypt-data-in-python-with-salt?msclkid=e9b69309bed011ec9776e5f1316c9769
    def auth_setup(self,pw):        
        salt = get_random_bytes(SALT_SIZE)
        pw_salt = pw.encode() + salt
        for i in range(NUMBER_OF_ITERATIONS):
            pw_salt = hashlib.sha256(pw_salt).digest()
        salt = int.from_bytes(salt, "big")
        pw_salt = int.from_bytes(pw_salt, "big")
        return [salt,pw_salt] # output in bytes
    
    #https://devrescue.com/python-rsa-encrypt-with-public-key/?msclkid=03be053cbedc11ec953a1c5dfa1055de
    def gen_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        # use key = RSA.import_key(open('public_key.pem').read())
        return [public_key.decode(), private_key.decode()] 

    # send this to query process unit
    def prv_key_hash(self,prv_key):
        prv_salt = prv_key.encode()
        for i in range(NUMBER_OF_ITERATIONS):
            prv_salt = hashlib.sha256(prv_salt).digest()
        prv_salt = int.from_bytes(prv_salt, "big")
        return prv_salt

class patient(client):
    def __init__(self):
        super().__init__()
        self.role = 3
        self.patientRecord = None
        self.patientRecordUsage = None
    
    def setup_new_client(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 3
        self.patientRecord = [] # record structure? only store record ID/hash
        self.patientRecordUsage = [] # record structure? only store record ID/hash
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, patientRecord, patientRecordUsage):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash)
        self.role = role
        self.patientRecord = patientRecord # record structure? only store record ID/hash
        self.patientRecordUsage = patientRecordUsage # record structure? only store record ID/hash
    
    def check_variables(self): # for test use
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



def load_patient_record():
    print()

def export_client(client):
    jsonStr = json.dumps(client.__dict__)
    # print(jsonStr)
    return jsonStr

def load_client(json_str):
    l = json.loads(json_str)
    # print(l)
    t_patient = patient()
    t_patient.recover_client(l['role'], l['ID'], l['username'], l['auth'], l['keypair'], l['prvKey_hash'], l['patientRecord'], l['patientRecordUsage'])
    t_patient.check_variables()

test_patient = patient()
test_patient.setup_new_client('alice','password')
# test_patient.check_variables()
test_patient2 = patient()
test_patient2.setup_new_client('bob','password')
p_list = [test_patient,test_patient2]

jsonS = export_client(test_patient)
# load_client(jsonS)
