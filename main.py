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

def rebuild_records(record_storage_unit):
    with open('records_list.json','r') as file:
        records_dict = json.load(file)
        for r in records_dict:
            record = recover_record_from_json(r)
            record_storage_unit.add_record(record)
    # print(record_storage_unit.record_dic)
            
def rebuild_events(query_process_unit):
    with open('events_list.json','r') as file:
        events_dict = json.load(file)
        for e in events_dict:
            event = recover_event_from_json(e)
            query_process_unit.add_event(event)

def rebuild_clients(client_verify_unit):
    with open('patients_list.json','r') as file:
        data = json.load(file) # json.loads(json_str)
        for item in data:
            p_obj = load_patient(item)
            # add to client_verify
            client_verify_unit.add_client(p_obj.username,p_obj.ID,p_obj.prvKey_hash)
            client_verify_unit.add_client_obj(p_obj.ID,p_obj)
    
    with open('aduit_companys_list.json','r') as file:
        data = json.load(file) # json.loads(json_str)
        for item in data:
            a_obj = load_audit(item)
            # add to client_verify
            client_verify_unit.add_client(a_obj.username,a_obj.ID, a_obj.prvKey_hash)
            client_verify_unit.add_client_obj(a_obj.ID,a_obj)
        
def rebuild_environment(query_process_unit,record_storage_unit,client_verify_unit):
    rebuild_records(record_storage_unit)
    rebuild_events(query_process_unit)
    rebuild_clients(client_verify_unit)

'''
requestor obj: patient/doctor/auidt
patient obj: patient

Loop: every record of a patient have a single query & event
'''
def query_record(requestor_obj, patient_obj):  
    if(client_verify.verify_identity(requestor_obj.ID,requestor_obj.prvKey_hash)):
        # pass identity verify
        patient_record_list = patient_obj.get_record_list()
        for id in patient_record_list:
            patient_obj.query_record(id) # write to file
            query_event = event()
            query_event.crete_new_event(requestor_obj.ID,patient_obj.ID,id,QUERY)

            query_process.receive_query(requestor_obj.keypair[0])# get true
            record_storage.get_query_from_processor()
            get_query_result(requestor_obj.keypair[1])

            query_event.status = True
            query_event.update_hash()
            query_process.add_event(query_event)
            requestor_obj.eventHistory.append(query_event.eventID)
            patient_obj.p_records_use.append(query_event.eventID)
        
    else:
        print("identity verify fail in query process")
        query_event = event()
        query_event.crete_new_event(requestor_obj.ID,patient_obj.ID,None,QUERY)
        query_event.status = False
        query_event.update_hash()
        query_process.add_event(query_event)
        requestor_obj.eventHistory.append(query_event.eventID)
        patient_obj.p_records_use.append(query_event.eventID)

def audit_query_record(audit_obj, choice):
    # check if choice exists
    if choice in client_verify.client_dic.keys():
        client_obj = client_verify.client_dic.get(choice)
        query_record(audit_obj,client_obj)
    else:
        print('patient do not exists')

def audit_query_all_record(audit_obj):
    patients = client_verify.client_dic.values()
    for p in patients:
        if(p.role == 2):
            query_record(audit_obj,p)

'''
patient_obj: patient object
'''
def patient_menu(patient_obj):
    exitFlag = False
    while(not exitFlag):
        print("Menu: \n0 - show user info \n1 - show user record \n2 - show user record usage \n9-exit")
        option = input("Enter your choice: ")
        if(option=='9'):
            print("Exit!")
            exitFlag=True
        if(option=='0'):
            patient_obj.print_info()
        if(option=='1'):
            query_record(patient_obj, patient_obj)
        if(option=='2'):
            patient_obj.get_record_usage()

def audit_menu(audit_obj):
    exitFlag = False
    while(not exitFlag):
        print("Menu: \n0 - show user info \n1 - show a specific patient's record  \n2 - show all patients' record \n9-exit")
        option = input("Enter your choice: ")
        if(option=='9'):
            print("Exit!")
            exitFlag=True
        if(option=='0'):
            audit_obj.print_info()
        if(option=='1'):
            client_verify.show_patient_id()
            client_id = input("Enter your choice: ")
            audit_query_record(audit_obj,int(client_id))
        if(option=='2'):
            audit_query_all_record(audit_obj)

def main():
    rebuild_environment(query_process,record_storage,client_verify)
    username = input("Enter client username: ")
    # check user_id in the db
    pw = input("Enter password: ")
    # check pw hash
    verified_client = client_verify.login_verify(username,pw)
    if(verified_client != False):
        if(verified_client.role == 2):
            patient_menu(verified_client)        
        if(verified_client.role == 1):
            audit_menu(verified_client)
    else: 
        print("wrong pw")

main()