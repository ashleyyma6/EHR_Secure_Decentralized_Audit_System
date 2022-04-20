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
        return hashlib.sha256(record.encode()).digest()
    
    def print_record(self):
        print("Record ID: ",self.recordID)
        print("Record create time: ",self.date_time)
        print("patient ID: ",self.patientID)
        print("Content: ",self.content)

def recover_record_from_json(json_dic):
    rec = record()
    rec.recover_record(json_dic['date_time'], json_dic['patientID'], json_dic['content'], json_dic['recordID'])
    return rec


def decrypt_query_result(encrypted_records, private_key):
    decrypted_records = []
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    for item in encrypted_records:
        plaintext = cipher.decrypt(item)
        decrypted_records.append(plaintext.decode())
    return decrypted_records

def get_query_result(private_key):
    with open('query_result.json', 'r') as file:
        data = json.load(file)
        decrypted_list = decrypt_query_result(data,private_key)
        record_list = []
        print("==== Record ====")
        for item in decrypted_list:
            r = recover_record_from_json(item)
            r.print_record()
            print("-------")
