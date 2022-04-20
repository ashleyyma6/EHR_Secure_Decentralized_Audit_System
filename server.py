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

class query_process_unit():
    def __init__(self):
        self.client_dic = {} # client dictionary = clientID : prvkeyHash
        self.query_dic = {} # query dictionary = eventID(hash) : event json str
    
    def receive_query(self, clientID, prvkeyHash, publicKey):
        if(self.verify_identity(clientID,prvkeyHash)):
            with open('query_record_list.json','r') as file:
                record_ID_list = json.load(file)
                self.send_query_to_db(record_ID_list, publicKey)
            return True
        else:
            return False

    def verify_identity(self,clientID,prvkeyHash):
        if(prvkeyHash == self.client_dic.get(clientID)):
            return True
        return False
    
    def send_query_to_db(record_ID_list, publicKey):
        with open('query_to_db.json','w') as file:
            output = [record_ID_list,publicKey]
            json.dump(output,file)
    
    def receive_record_from_db():
        with open('query_to_db','w') as file:
            ecnrypted_data = file.read()
            return ecnrypted_data

class record_storage_unit():
    def __init__(self):
        # record dic entry = {record hash: record obj (json str)}
        self.record_dic = {}
    
    def load_record(self):
        with open('record_db','r') as file:
            json.load(file.read())
    
    def get_query_from_processor(self):
        with open('query_to_db.json','r') as file:
            data = json.load(file)
            query_recordID_list = data[0]
            query_pub_key = data[1]
            self.send_record_result(query_recordID_list, query_pub_key)

    def send_record_result(self, query_recordID_list, query_pub_key):
        encrypted = self.encrypt_records(query_recordID_list, query_pub_key)
        with open('query_result.json','w') as file:
            json.dump(encrypted, file)

    def encrypt_records(self,query_recordID_list, query_pub_key):
        encrypted_records = []
        for item in query_recordID_list: 
            record = self.record_dic.get(item)
            record_json = json.dumps(record)
            pub_key = RSA.import_key(query_pub_key)
            cipher = PKCS1_OAEP.new(pub_key)
            ciphertext = cipher.encrypt(record_json)
            encrypted_records.append(ciphertext)
        return encrypted_records
    
    def add_record(self,record_obj):
        self.record_dic.update({record_obj.recordHash:record_obj})

class client_verify_unit():
    def __init__(self):
        self.username_dic = {} # username : clientID
        self.client_dic = {} #  patientID : patient obj