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
        # print(records_dict)
        for r_index in records_dict.keys():
            record_storage_unit.add_record(int(r_index), records_dict.get(r_index))
            
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

# ===== Exit & save Environment =====
def exit_client(client_verify_unit):
    client_list = client_verify_unit.client_dic.values()
    aduit_companys_list = []
    patients_list = []
    for c in client_list:
        if(c.role == 1):
            aduit_companys_list.append(c._as_dict_())
        if (c.role == 2):
            patients_list.append(c._as_dict_())  
    with open('patients_list.json','w') as file:
        json.dump(patients_list,file)        
    with open('aduit_companys_list.json','w') as file:
        json.dump(aduit_companys_list,file)

def exit_record(record_storage_unit):
    records = record_storage_unit.get_all_records()
    records_dict = []
    for r in records:
        records_dict.append(r._as_dict_())
    with open('records_list.json','w') as file:
        json.dump(records_dict,file)

def exit_event(query_process_unit):
    # export events
    events = query_process_unit.get_all_events()
    events_dict = []
    for e in events:
        events_dict.append(e._as_dict_())
    with open('events_list.json','w') as file:
        json.dump(events_dict,file)

def exit(query_process_unit, record_storage_unit, client_verify_unit):
    exit_client(client_verify_unit)
    exit_record(record_storage_unit)
    exit_event(query_process_unit)

# ===== Query =====
'''
requestor obj: patient/doctor/auidt
patient obj: patient

Loop: every record of a patient have a single query & event
'''
def query_record(requestor_obj, patient_obj):  
    if(client_verify.verify_identity(requestor_obj.ID,requestor_obj.prvKey_hash)):
        # pass identity verify
        print("======= print "+patient_obj.username+"'s record ======")
        patient_record_list = patient_obj.get_record_list()
        if(len(patient_record_list)<1):
            print("None")
            return
        for id in patient_record_list:
            patient_obj.query_record(id) # write to file
            query_event = event()
            query_event.crete_new_event(requestor_obj.ID,patient_obj.ID,id,QUERY)

            query_process.receive_query(requestor_obj.decrypt_s_key())# get true
            record_storage.get_query_from_processor()
            get_query_result(requestor_obj.decrypt_s_key())

            query_event.status = True
            query_event.update_hash()
            query_process.add_event(query_event)
            #query_event.print_event()
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
            # if(p.username!='bob'):
            #     query_record(audit_obj,p)

# ===== Event history =====
def get_event_history(requestor_obj, patient_obj):
    if(client_verify.verify_identity(requestor_obj.ID,requestor_obj.prvKey_hash)):
        # pass identity verify
        patient_record_use_list = patient_obj.get_record_usage()
        #print(len(patient_record_use_list))
        print("======= print "+patient_obj.username+"'s record activity ======")
        if(len(patient_record_use_list)<1):
            print("None")
            return
        for id in patient_record_use_list:
            #print("event id: ", id)
            patient_obj.query_reocrd_use(id) # write to file
            query_process.receive_use_query(requestor_obj.decrypt_s_key())# get true
            get_query_use_result(requestor_obj.decrypt_s_key())
    else:
        print("identity verify fail in query process")

def audit_query_event(audit_obj, choice):
    # check if choice exists
    if choice in client_verify.client_dic.keys():
        client_obj = client_verify.client_dic.get(choice)
        get_event_history(audit_obj,client_obj)
    else:
        print('patient do not exists')

def audit_query_all_events(audit_obj):
    patients = client_verify.client_dic.values()
    for p in patients:
        if(p.role == 2):
            get_event_history(audit_obj,p)
            # if(p.username!='bob'):
            #     query_record(audit_obj,p)

# ===== Menu
def patient_menu(patient_obj):
    exitFlag = False
    while(not exitFlag):
        print("Menu: \n0 - show user info \n1 - show user record \n2 - show user record usage \n9-exit")
        option = input("Enter your choice: ")
        if(option=='9'):
            print("Exit!")
            #exit(query_process,record_storage,client_verify)
            exitFlag=True
        if(option=='0'):
            patient_obj.print_info()
        if(option=='1'):
            query_record(patient_obj, patient_obj)
        if(option=='2'):
            get_event_history(patient_obj, patient_obj)

def audit_menu(audit_obj):
    exitFlag = False
    while(not exitFlag):
        print("Menu: \n0 - show user info\n1 - show a specific patient's record\n2 - show all patients' record\n")
        print("3 - show a specific patient's activity\n4 - show all patients' activity\n9-exit")
        option = input("Enter your choice: ")
        if(option=='9'):
            print("Exit!")
            #exit(query_process,record_storage,client_verify)
            exitFlag=True
        if(option=='0'):
            audit_obj.print_info()
        if(option=='1'):
            client_verify.show_patient_id()
            client_id = input("Enter your choice: ")
            audit_query_record(audit_obj,int(client_id))
        if(option=='2'):
            audit_query_all_record(audit_obj)
        if(option=='3'):
            client_verify.show_patient_id()
            client_id = input("Enter your choice: ")
            audit_query_event(audit_obj,int(client_id))
        if(option=='4'):
            audit_query_all_events(audit_obj)

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
        print("Message: wrong pw")

main()