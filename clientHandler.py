import hashlib
import random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json

# https://stackoverflow.com/questions/51975664/serialize-and-deserialize-objects-from-user-defined-classes

# salt size in bytes
SALT_SIZE = 16
# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 5

'''
byte to int
int.from_bytes(byte_val, "big")

int to byte
int_val.to_bytes(length, byteorder)

Reference
https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
'''

class client():
    def __init__(self):
        self.role = None # int
        self.ID = None # int
        self.username = None # str
        self.auth = None # [byte, byte]
        self.keypair = None # [str, str] AES prv, pub
        self.prvKey_hash = None # int
        self.eventHistory = [] # [hash, hash ... ]
    
    def _as_dict_(self):
        dic = {'role':self.role,
            'ID': self.ID,
            'username':self.username,
            'auth':[int.from_bytes(self.auth[0],'big'), int.from_bytes(self.auth[1],'big')],
            'keypair':self.keypair,
            'prvKey_hash':self.prvKey_hash,
            'eventHistory':self.eventHistory}
        return dic

    def setup_new_client(self, username, pw):
        self.role = 0
        self.ID = random.getrandbits(10) # remember check repeat
        self.username = username # for login
        self.auth = self.auth_setup(pw) # salt(byte->int)，password_hash(byte->int)
        self.keypair = self.gen_key_pair() 
        self.prvKey_hash = self.set_prvkey_hash(self.keypair[1])
        self.eventHistory = []
    
    def recover_client(self, role, ID, username, auth, keypair, prvKey_hash, eventHistory):
        self.role = role # int
        self.ID = ID # int
        self.username = username # str
        self.auth = auth # [int, int] -> [byte, byte]
        self.keypair = keypair # [str, str]
        self.prvKey_hash = prvKey_hash # int
        self.eventHistory = eventHistory # [hash, hash ... ]

    '''
    pw: str
    
    output: [str, str] 
    str for json
    Reference: https://stackoverflow.com/questions/6425131/encrypt-decrypt-data-in-python-with-salt
    '''
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
        return [public_key.decode(), private_key.decode()] 

    # send this to query process unit
    def set_prvkey_hash(self,prv_key):
        prv_salt = prv_key.encode()
        for i in range(NUMBER_OF_ITERATIONS):
            prv_salt = hashlib.sha256(prv_salt).digest()
        prv_salt = int.from_bytes(prv_salt, "big")
        return prv_salt
    
    def print_info(self):
        print("Role: ",str(self.role))
        print("ID: ",str(self.ID))
        print("Username: ",self.username)

class audit_company(client):    
    def __init__(self):
        super().__init__()
        self.role = 1
    
    def _as_dict_(self):
        dic = super()._as_dict_()
        dic['role'] = self.role
        return dic
    
    def setup_new_audit(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 1
    
    def recover_audit(self, role, ID, username, auth, keypair, prvKey_hash, actionHistory):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash, actionHistory)
        self.role = role

class patient(client):
    def __init__(self):
        super().__init__()
        self.role = 2
        self.p_records = None
        self.p_records_use = None
    
    def _as_dict_(self):
        dic = super()._as_dict_()
        dic['role'] = self.role
        dic['p_records'] = self.p_records
        dic['p_records_use'] = self.p_records_use
        return dic
    
    def setup_new_patient(self, username, pw):
        super().setup_new_client(username, pw)
        self.role = 2
        self.p_records = [] # only store record ID/hash
        self.p_records_use = [] # only store record ID/hash
    
    def recover_patient(self, role, ID, username, auth, keypair, prvKey_hash, eventHistory, p_records, p_records_use):
        super().recover_client(role, ID, username, auth, keypair, prvKey_hash, eventHistory)
        self.role = role
        self.p_records = p_records
        self.p_records_use = p_records_use
    
    def query_record(self, recordID):
        if recordID in self.p_records:
            with open('query_record', 'w') as file:
                file.write(str(recordID))
        else:
            print("invalid record ID")
    
    def get_record_list(self):
        return self.p_records

    def get_record_usage_get_record_list(self):
        return self.p_records_use
    
    def add_pRecord(self,recordID):
        self.p_records.append(recordID)

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
        audits = data['audit']
        patient_list = []
        audit_list = []
        for item in patients:
            p = patient()
            p.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'], item['patientRecord'], item['patientRecordUsage'])
            patient_list.append(p)
        for item in audits:
            a = audits()
            a.recover_client(item['role'], item['ID'], item['username'], item['auth'], item['keypair'], item['prvKey_hash'], item['actionHistory'])
            audit_list.append(a)       

def load_patient(patient_json): # json_str
    p = patient()
    p.recover_patient(patient_json['role'], patient_json['ID'], patient_json['username'], patient_json['auth'], patient_json['keypair'], patient_json['prvKey_hash'], patient_json['eventHistory'], patient_json['p_records'], patient_json['p_records_use'])
    return p

def load_audit(audit_json):
    a = audit_company()
    a.recover_audit(audit_json['role'], audit_json['ID'], audit_json['username'], audit_json['auth'], audit_json['keypair'], audit_json['prvKey_hash'], audit_json['eventHistory'])
    return a
