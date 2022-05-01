import datetime
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

class record():
    def __init__(self):
        self.date_time = None # str, creation datetime 
        self.patientID = None # int
        self.content = None # str
        self.recordID = None # int, record ID
    
    def _as_dict_(self):
        dict = {
            'date_time':self.date_time,
            'patientID':self.patientID,
            'content':self.content,
            'recordID':self.recordID
        }
        return dict

    def create_new_record(self,patientID,content):
        self.date_time = str(datetime.datetime.now()) #
        self.patientID = patientID
        self.content = content # assume string
        self.recordID = self.gen_hash()
    
    def recover_record(self, date_time, patientID, content, recordID):
        self.date_time = date_time
        self.patientID = patientID
        self.content = content
        self.recordID = recordID

    def gen_hash(self):
        record = self.date_time+str(self.patientID)+self.content
        hash = hashlib.sha256(record.encode()).digest()
        hash = int.from_bytes(hash, "big")
        return hash
    
    def print_record(self):
        print("Record ID: ",self.recordID)
        print("Record create time: ",self.date_time)
        print("patient ID: ",self.patientID)
        print("Content: ",self.content)

def recover_record_from_json(json_dic):
    rec = record()
    rec.recover_record(json_dic['date_time'], json_dic['patientID'], json_dic['content'], json_dic['recordID'])
    return rec

def decrypt_query_result(encrypted_record, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(encrypted_record)
    return plaintext.decode()

def get_query_result(private_key):
    with open('query_result.json', 'r') as file:
        data = json.load(file)
        data = data.to_bytes((data.bit_length()+7)//8,'big')
        decrypted = decrypt_query_result(data, private_key)
        decrtpted_r = recover_record_from_json(json.loads(decrypted))
        decrtpted_r.print_record()
        print("-------")
