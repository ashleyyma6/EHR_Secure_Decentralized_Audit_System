import datetime
import hashlib

CREAT=0
DELETE=1
MODIFY=2
QUERY=3

class event():
    def __init__(self):
        self.date_time = None
        self.requestorID = None
        self.patientID = None
        self.recordID = None
        self.actionType = None
        self.status = None #T/F
        self.eventID = None
    
    def crete_new_event(self,requestorID,patientID,recordID,actionType):
        self.date_time = datetime.datetime.now() #creation datetime
        self.requestorID = requestorID
        self.patientID = patientID
        self.recordID = recordID
        self.actionType = actionType
        self.status = None #T/F
        self.eventID = self.update_hash()
    
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
        print("Record ID: ",self.recordID)
        print("Action: ",self.actionType)
        print("Status: ",self.status)

    def update_hash(self):
        event = self.date_time+str(self.requestorID)+str(self.patientID)+str(self.recordID)+str(self.actionType)+str(self.status)
        return hashlib.sha256(event.encode()).digest()
    
def recover_event_from_json(json_dic):
    eve = event()
    eve.recover_event(json_dic['date_time'], json_dic['requestorID'], json_dic['patientID'], json_dic['recordID'], json_dic['actionType'], json_dic['status'])
    return eve
