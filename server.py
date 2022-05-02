'''
Use dictionary
record dic entry = {record hash:record obj}
query dic entry = {queryhash:query obj}

query_process_unit: receive query, verify identity, get record from db
add eventhistory to all needed place 
'''
import json
from eventHandler import *
from recordHandler import *
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 5

class query_process_unit():
    def __init__(self):
        self.event_dic = {} # query dictionary = eventID(hash) : event json str
    
    def get_all_events(self):
        return self.event_dic.values()
    
    def add_event(self,event_obj):
        self.event_dic.update({event_obj.eventID:event_obj})

    def receive_query(self, requestor_s_key):
        with open('query_record.json','r') as file:
            content = json.load(file)
            record_ID=content[0]
            s_key=content[1]
            self.send_query_to_db(record_ID, s_key, requestor_s_key)

    def send_query_to_db(self, record_ID, s_key, requestor_s_key):
        with open('query_to_db.json','w') as file:
            output = [record_ID, s_key, requestor_s_key]
            json.dump(output,file)
    
    def receive_record_from_db(self):
        with open('query_to_db','w') as file:
            ecnrypted_data = file.read()
            return ecnrypted_data
    
    def encrypt_event(self, event_ID, requestor_sKey):
        event = self.event_dic.get(event_ID)._as_dict_()
        event_json = json.dumps(event)
        plaintext = event_json.encode()
        key = requestor_sKey.to_bytes((requestor_sKey.bit_length()+7)//8,'big')
        nonce = get_random_bytes(15)
        cipher = AES.new(key, AES.MODE_OCB, nonce)
        ciphertext, mac = cipher.encrypt_and_digest(plaintext)
        return [int.from_bytes(ciphertext, "big"), int.from_bytes(nonce, "big"),int.from_bytes(mac, "big")]

    def send_use_record(self, event_ID, requestor_sKey):
        encrypted = self.encrypt_event(event_ID, requestor_sKey)
        with open('query_use_result.json','w') as file:
            json.dump(encrypted, file)

    def receive_use_query(self, requestor_sKey):
        with open('query_record_use','r') as file:
            event_ID = int(file.read())
            if event_ID in self.event_dic.keys():
                self.send_use_record(event_ID,requestor_sKey)
            
class record_storage_unit():
    def __init__(self):
        # record dic entry = {record hash: record obj (json str)}
        self.record_dic = {}
    
    def get_all_records(self):
        return self.record_dic
    
    def load_record(self):
        with open('record_db','r') as file:
            json.load(file.read())
    
    def add_record(self,recordID, encrypted_record):
        self.record_dic.update({recordID:encrypted_record})
    
    def get_query_from_processor(self):
        with open('query_to_db.json','r') as file:
            data = json.load(file)
            # print("get_query_from_processor")
            # print(data)
            query_recordID = data[0]
            query_s_key = data[1]
            requestor_s_key = data[2]
            self.send_record_result(query_recordID, query_s_key,requestor_s_key)

    def send_record_result(self, query_recordID, query_s_key, requestor_s_key):
        decrypted_record = self.decrypt_records(query_recordID, query_s_key)
        # print("decrypted_record")
        # print(decrypted_record)
        encrypted = self.encrypt_records(decrypted_record, requestor_s_key)
        # print("send_record_result")
        # print(encrypted)
        with open('query_result.json','w') as file:
            json.dump(encrypted, file)

    def encrypt_records(self,decrypted_record, requestor_s_key):
        key = requestor_s_key.to_bytes((requestor_s_key.bit_length()+7)//8,'big')
        nonce = get_random_bytes(15)
        cipher = AES.new(key, AES.MODE_OCB, nonce)
        plaintext = decrypted_record
        ciphertext, mac = cipher.encrypt_and_digest(plaintext)
        return [int.from_bytes(ciphertext, "big"), int.from_bytes(nonce, "big"),int.from_bytes(mac, "big")]
    
    def decrypt_records(self, query_recordID, query_s_key):
        encrypted_record = self.record_dic.get(query_recordID)
        # print(encrypted_record)
        key=query_s_key.to_bytes((query_s_key.bit_length()+7)//8,'big')
        ciphertext=encrypted_record[0].to_bytes((encrypted_record[0].bit_length()+7)//8,'big')
        nonce=encrypted_record[1].to_bytes((encrypted_record[1].bit_length()+7)//8,'big')
        mac=encrypted_record[2].to_bytes((encrypted_record[2].bit_length()+7)//8,'big')
        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, mac)
        except ValueError:
            # print ("Invalid message after receive query & decrypt record")
            with open('error_log','a') as file:
                err = str(datetime.datetime.now())+"--Invalid message--"+str(query_recordID)+"\n"
                file.write(err)
                sys.exit("Invalid message")
        else:
            return plaintext # byte str

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