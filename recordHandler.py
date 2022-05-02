import datetime
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys


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
        plaintext = record_decryption(private_key, data)
        decrtpted_r = recover_record_from_json(json.loads(plaintext))
        decrtpted_r.print_record()
        print("-------")

def record_encryption(sKey, record_obj):
    key = sKey
    nonce = get_random_bytes(15)
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    record_json = json.dumps(record_obj._as_dict_())
    plaintext = record_json.encode()
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)
    return [int.from_bytes(ciphertext, "big"), int.from_bytes(nonce, "big"),int.from_bytes(mac, "big")]

def record_decryption(sKey, encrypted_record):
    key=sKey.to_bytes((sKey.bit_length()+7)//8,'big')
    ciphertext=encrypted_record[0].to_bytes((encrypted_record[0].bit_length()+7)//8,'big')
    nonce=encrypted_record[1].to_bytes((encrypted_record[1].bit_length()+7)//8,'big')
    mac=encrypted_record[2].to_bytes((encrypted_record[2].bit_length()+7)//8,'big')
    cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    except ValueError:
        # print ("Invalid message in the decryption right before output")
        sys.exit("Invalid message")
    else:
        return plaintext
