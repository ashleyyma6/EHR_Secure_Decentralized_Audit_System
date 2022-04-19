import datetime
'''
Action code
create=0
delete=1
modify=2
request=3
print=4
copy=5
'''
class query():
    def __init__(self,requestorID,patientID,recordHash):
        self.datetime = datetime.datetime.now() #creation datetime
        self.requestorID = requestorID
        self.patientID = patientID
        self.recordHash = recordHash
        self.actionType = ""