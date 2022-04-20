import sys
import hashlib
from Crypto.Random import get_random_bytes
from clientHandler import *
from recordHandler import *
from eventHandler import *
from server import *

# ===== set up environment =====
query_process = query_process_unit()
# load event history
record_storage = record_storage_unit()
# load record
client_verify = client_verify_unit()
# load client

#finish
def login_verify(username,pw):
    if username in client_verify.username_dic.keys():
        client_id = client_verify.username_dic.get(username)
        client_obj = client_verify.client_dic.get(client_id)
        client_auth = client_obj.auth
        if auth_verify(pw,client_auth):
            return client_obj
        else:
            return False
    else:
        return False

# requestor obj, patient obj
def query_record(requestor_obj, patient_obj):
    query_event = event()
    query_event.crete_new_event(requestor_obj.ID,patient_obj.ID,patient_obj.patientRecord,QUERY)

    patient_obj.query_record() # write to file
    process_result = query_process.receive_query(requestor_obj.ID,requestor_obj.prvKey_hash,requestor_obj.keypair[1])# get true
    if(process_result):
        query_event.status = True
        query_event.update_hash()
        requestor_obj.eventHistory.append(query_event.eventID)
        patient_obj.patientRecordUsage.append(query_event.eventID)
        record_storage.get_query_from_processor()
        get_query_result(requestor_obj.keypair[0])
    else:
        print("identity verify fail in query process")

def patient_menu(patient_obj):
    print("Menu: 0-show user info 1-show user record 2-show user record usage 9-exit")
    option = input("Enter your choice: ")
    exitFlag = False
    while(not exitFlag):
        if(option==9):
            print("Exit!")
            exitFlag=True
        if(option==0):
            patient_obj.print_info()
        if(option==1):
            print()
        if(option==2):
            patient_obj.get_record_usage()
        
def doctor_menu(doctor_obj):
    print()

def audit_menu(audit_obj):
    print()

def main():
    user_id = input("Enter client ID: ")
    # check user_id in the db
    pw = input("Enter password: ")
    # check pw hash
    verified_client = login_verify(user_id,pw)
    if(verified_client.role != False):
        if(verified_client.role == 3):
            patient_menu(verified_client)        
        if(verified_client.role == 2):
            doctor_menu(verified_client)  
        if(verified_client.role == 1):
            audit_menu(verified_client)

# main()