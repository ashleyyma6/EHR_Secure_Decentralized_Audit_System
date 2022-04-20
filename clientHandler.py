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
        self.eventHistory = []

    def setup_new_client(self, username, pw):
        self.role = 0
        self.ID = random.getrandbits(10) # remember check repeat
        self.username = username # for login
        self.auth = self.auth_setup(pw) # salt(plaintext)，password_hash(hash with salt, do not store pw)
        self.keypair = self.gen_key_pair() 
        self.prvKey_hash = self.prv_key_hash(self.keypair[1])
        self.eventHistory = []
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, eventHistory):
        self.role = role #int
        self.ID = ID #int
        self.username = username #str
        self.auth = auth # [int, int]
        self.keypair = keypair # [str, str]
        self.prvKey_hash = prvKey_hash # int
        self.eventHistory = eventHistory # [hash, hash ... ]

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
    
    def print_info(self):
        print("Role: ",self.role)
        print("ID: ",self.ID)
        print("Username: ",self.username)

class patient(client):
    def __init__(self):
        super().__init__()
        self.role = 3
        self.actionHistory = None
        self.patientRecord = None
        self.patientRecordUsage = None
    
    def setup_new_client(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 3
        self.patientRecord = [] # record structure? only store record ID/hash
        self.patientRecordUsage = [] # record structure? only store record ID/hash
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, eventHistory, patientRecord, patientRecordUsage):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash, eventHistory)
        self.role = role
        self.patientRecord = patientRecord # record structure? only store record ID/hash
        self.patientRecordUsage = patientRecordUsage # record structure? only store record ID/hash
    
    def query_record(self):
        with open('query_record_list.json', 'w') as file:
            json.dump(self.patientRecord ,file)
    
    def get_record_usage():
        print()
        
class doctor(client):
    def __init__(self):
        super().__init__()
        self.role = 2
        self.actionHistory = None
    
    def setup_new_client(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 2
        self.actionHistory = [] # record structure? only store query ID/hash
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, actionHistory):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash, actionHistory)
        self.role = role
    
    def create_record():
        print()
    
    def query_record():
        print()

class audit_company(client):    
    def __init__(self):
        super().__init__()
        self.role = 1
        self.actionHistory = None
    
    def setup_new_client(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 1
        self.actionHistory = [] # record structure? only store query ID/hash
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, actionHistory):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash, actionHistory)
        self.role = role
    
    def query_record():
        print()

# client_type: patient, doctor, audit
def export_client(client_list, client_type): 
    # jsonStr = json.dumps([client.__dict__ for client in client_list])
    # print(jsonStr)
    # return jsonStr
    with open(client_type+'_list.json', 'w') as file:
        json.dump([client.__dict__ for client in client_list], file)

def load_client():
    with open('client_list.json', 'r') as file:
        data = json.load(file)
        patients = data['patient']
        doctors = data['doctor']
        audits = data['audit']
        patient_list = []
        doctor_list = []
        audit_list = []
        for item in patients:
            p = patient()
            p.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'], item['patientRecord'], item['patientRecordUsage'])
            patient_list.append(p)
        for item in doctors:
            d = doctor()
            d.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'])
            doctor_list.append(d)
        for item in audits:
            a = doctor()
            a.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'])
            audit_list.append(a)       

def load_patient(): # json_str
    with open('patient_list.json', 'r') as file:
        data = json.load(file) # json.loads(json_str)
        # print(data)
        patient_list = []
        for item in data:
            p = patient()
            p.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'], item['patientRecord'], item['patientRecordUsage'])
            # p.check_variables()
            patient_list.append(p)
        return patient_list

def load_dr():
    with open('doctor_list.json', 'r') as file:
        data = json.loads(file) # json.loads(json_str)
        # print(data)
        doctor_list = []
        for item in data:
            d = doctor()
            d.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'])
            doctor_list.append(d)
        return doctor_list

def load_audit():
    with open('audit_list.json', 'r') as file:
        data = json.loads(file) # json.loads(json_str)
        # print(data)
        audit_list = []
        for item in data:
            a = doctor()
            a.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'])
            audit_list.append(a)
        return audit_list

def auth_verify(password, auth):
    pw_salt = password.encode() + auth[0]
    # number of iterations in the key generation
    NUMBER_OF_ITERATIONS = 20
    for i in range(NUMBER_OF_ITERATIONS):
        pw_salt = hashlib.sha256(pw_salt).digest()
    return (pw_salt == auth[1])





