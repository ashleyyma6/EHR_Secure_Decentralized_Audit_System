import datetime
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys

CREAT=0
DELETE=1
MODIFY=2
QUERY=3

class event():
    def __init__(self):
        self.date_time = None # str
        self.requestorID = None # int
        self.patientID = None # int
        self.recordID = None # int
        self.actionType = None # int
        self.status = None # T/F
        self.eventID = None # int

    def _as_dict_(self):
        dict = {
            'date_time':str(self.date_time),
            'requestorID':self.requestorID,
            'patientID':self.patientID,
            'recordID':self.recordID,
            'actionType':self.actionType,
            'status':self.status,
            'eventID':self.eventID
        }
        return dict
    
    def crete_new_event(self,requestorID,patientID,recordID,actionType):
        self.date_time = datetime.datetime.now() #creation datetime
        self.requestorID = requestorID
        self.patientID = patientID
        self.recordID = recordID
        self.actionType = actionType
        self.status = None #T/F
    
    def recover_event(self,date_time,requestorID,patientID,recordID,actionType,status, eventID):
        self.date_time = date_time
        self.requestorID = requestorID
        self.patientID = patientID
        self.recordID = recordID
        self.actionType = actionType
        self.status = status
        self.eventID = eventID
    
    def print_event(self):
        print("Time: ",self.date_time)
        print("Requestor ID: ",self.requestorID)
        print("Patient ID: ",self.patientID)
        print("Event ID: ",self.recordID)
        print("Action: ",self.actionType)
        print("Status: ",self.status)

    def update_hash(self):
        event = str(self.date_time)+str(self.requestorID)+str(self.patientID)+str(self.recordID)+str(self.actionType)+str(self.status)
        hash = hashlib.sha256(event.encode()).digest()
        hash = int.from_bytes(hash, "big")
        self.eventID = hash
        return hash
    
def recover_event_from_json(json_dic):
    eve = event()
    eve.recover_event(json_dic['date_time'], json_dic['requestorID'], json_dic['patientID'], json_dic['recordID'], json_dic['actionType'], json_dic['status'], json_dic['eventID'])
    return eve

def decrypt_query_use_result(encrypted_record, requestor_sKey):
    key=requestor_sKey.to_bytes((requestor_sKey.bit_length()+7)//8,'big')
    ciphertext=encrypted_record[0].to_bytes((encrypted_record[0].bit_length()+7)//8,'big')
    nonce=encrypted_record[1].to_bytes((encrypted_record[1].bit_length()+7)//8,'big')
    mac=encrypted_record[2].to_bytes((encrypted_record[2].bit_length()+7)//8,'big')
    cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    except ValueError:
        # print ("Invalid message after receive query & decrypt record")
        with open('error_log','a') as file:
            err = str(datetime.datetime.now())+"--Invalid message--when check activity\n"
            file.write(err)
            sys.exit("Invalid message")
    else:
        return plaintext # byte str

def get_query_use_result(requestor_sKey):
    with open('query_use_result.json', 'r') as file:
        data = json.load(file)
        plaintext = decrypt_query_use_result(data,requestor_sKey)
        # print(plaintext)
        decrtpted_e = recover_event_from_json(json.loads(plaintext))
        decrtpted_e.print_event()
        print("-------")

        
