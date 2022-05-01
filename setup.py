# hardcode client, record
# 5 patient, 1 doctor, 2 audit company
from clientHandler import *
from eventHandler import *
from server import *
from recordHandler import *


# 1 server stubs, 1 client stubs
#=====Server Side
query_process = query_process_unit()
record_storage = record_storage_unit()
client_verify = client_verify_unit()

#=====Client Side
# 5 patient, 2 audit
patients = ['alice','bob','carol','dave','eve']
aduit_companys = ['aduit1','audit2']
patients_list = []
aduit_companys_list = []

records_content = []
with open('record_contents.json','r') as file:
    records_content = json.load(file)
    #print(records_content)
record_index = 0

for p in patients:
    # patient object
    p_obj = patient()
    p_obj.setup_new_patient(p,p)
    
    # add to client_verify
    client_verify.add_client(p_obj.username,p_obj.ID,p_obj.prvKey_hash)
    client_verify.add_client_obj(p_obj.ID,p_obj)
    
    # setup patient records
    r1 = record()
    r1.create_new_record(p_obj.ID,records_content[record_index])
    record_storage.add_record(r1)
    p_obj.add_pRecord(r1.recordID)
    r2 = record()
    r2.create_new_record(p_obj.ID,records_content[record_index+1])
    record_storage.add_record(r2)
    p_obj.add_pRecord(r2.recordID)
    record_index+=2

    # for patient export
    patients_list.append(p_obj._as_dict_()) 

for a in aduit_companys:
    a_obj = audit_company()
    a_obj.setup_new_audit(a,a)
    
    client_verify.add_client(a_obj.username,a_obj.ID, a_obj.prvKey_hash)
    client_verify.add_client_obj(a_obj.ID,a_obj)
    
    aduit_companys_list.append(a_obj._as_dict_()) # for export

#=======================================================
# export patients
with open('patients_list.json','w') as file:
    json.dump(patients_list,file)
# export aduit companies
with open('aduit_companys_list.json','w') as file:
    json.dump(aduit_companys_list,file)
# export 2 client verify dict
# with open('client_verify.json','w') as file:
#     json.dump(client_verify._as_dict_(),file)

# export events
events = query_process.get_all_events()
events_dict = []
for e in events:
    events_dict.append(e._as_dict_())
with open('events_list.json','w') as file:
    json.dump(events_dict,file)

# export records
records = record_storage.get_all_records()
records_dict = []
for r in records:
    records_dict.append(r._as_dict_())
with open('records_list.json','w') as file:
    json.dump(records_dict,file)