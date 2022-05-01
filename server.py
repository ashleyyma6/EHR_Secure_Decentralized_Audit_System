'''
Use dictionary
record dic entry = {record hash:record obj}
query dic entry = {queryhash:query obj}

query_process_unit: receive query, verify identity, get record from db
add eventhistory to all needed place 
'''
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from eventHandler import *
from recordHandler import *

# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 5

class query_process_unit():
    def __init__(self):
        self.event_dic = {} # query dictionary = eventID(hash) : event json str
    
    def get_all_events(self):
        return self.event_dic.values()
    
    def add_event(self,event_obj):
        self.event_dic.update({event_obj.eventID:event_obj})

    def receive_query(self, publicKey):
        with open('query_record','r') as file:
            record_ID = file.read()
            self.send_query_to_db(record_ID, publicKey)

    def send_query_to_db(self, record_ID, publicKey):
        with open('query_to_db.json','w') as file:
            output = [record_ID, publicKey]
            json.dump(output,file)
    
    def receive_record_from_db(self):
        with open('query_to_db','w') as file:
            ecnrypted_data = file.read()
            return ecnrypted_data

class record_storage_unit():
    def __init__(self):
        # record dic entry = {record hash: record obj (json str)}
        self.record_dic = {}
    
    def get_all_records(self):
        return self.record_dic.values()
    
    def load_record(self):
        with open('record_db','r') as file:
            json.load(file.read())
    
    def add_record(self,record_obj):
        self.record_dic.update({record_obj.recordID:record_obj})
    
    def get_query_from_processor(self):
        with open('query_to_db.json','r') as file:
            data = json.load(file)
            print("get_query_from_processor")
            # print(data)
            query_recordID = data[0]
            query_pub_key = data[1]
            self.send_record_result(int(query_recordID), query_pub_key)

    def send_record_result(self, query_recordID, query_pub_key):
        encrypted = self.encrypt_records(query_recordID, query_pub_key)
        with open('query_result.json','w') as file:
            json.dump(encrypted, file)

    def encrypt_records(self,query_recordID, query_pub_key):
        record = self.record_dic.get(query_recordID)._as_dict_()
        record_json = json.dumps(record)
        pub_key = RSA.import_key(query_pub_key.encode())
        cipher = PKCS1_OAEP.new(pub_key)
        ciphertext = cipher.encrypt(record_json.encode())
        return int.from_bytes(ciphertext,'big')
    
class client_verify_unit():
    def __init__(self):
        self.username_dic = {} # username (str) : clientID (int)
        self.client_dic = {} #  clientID (int) : clientObj (obj)
        self.clientKey_dic = {} # client dictionary = clientID : prvkeyHash
    
    def _as_dict_(self):
        dict = {1:self.username_dic, 2:self.clientKey_dic}
        return dict

    def recover_dic_from_file():
        print(0)
    
    def add_client(self, username, clientID, prvkeyHash):
        self.username_dic[username] = clientID
        self.clientKey_dic[clientID] = prvkeyHash

    def add_client_obj(self, patientID, clientObj):
        self.client_dic[patientID] = clientObj

    #https://www.adamsmith.haus/python/answers/how-to-print-a-list-using-a-custom-format-in-python
    def show_patient_id(self):
        print(self.username_dic.values())

    def verify_identity(self,clientID,prvkeyHash):
        if(prvkeyHash == self.clientKey_dic.get(clientID)):
            return True
        return False
    
    '''
    password: str --> byte
    auth: [str?, str?] -> [int, int] -> [byte, byte]
        output: T/F
    '''
    def auth_verify(self, password, auth):
        pw_salt = password.encode() + auth[0].to_bytes((auth[0].bit_length() + 7) // 8, 'big')
        # number of iterations in the key generation
        for i in range(NUMBER_OF_ITERATIONS):
            pw_salt = hashlib.sha256(pw_salt).digest()
        return (pw_salt == auth[1].to_bytes((auth[1].bit_length() + 7) // 8, 'big'))

    '''
    username: str
    pw: str
        output: client object / False
    '''
    def login_verify(self, username,pw):
        if username in self.username_dic.keys():
            client_id = self.username_dic.get(username)
            client_obj = self.client_dic.get(client_id)
            client_auth = client_obj.auth
            if self.auth_verify(pw,client_auth):
                return client_obj
        return False