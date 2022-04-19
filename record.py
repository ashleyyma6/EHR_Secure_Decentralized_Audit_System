import datetime
import hashlib

class record():
    def __init__(self,patientID,content):
        self.datetime = datetime.datetime.now() #creation datetime
        self.patientID = patientID
        self.content = content # assume string
        self.recordHash = self.gen_hash()
    def gen_hash(self):
        record = str(self.datetime)+str(self.patientID)+self.content
        return hashlib.sha256(record.encode()).digest()
    def check_variables(self): #  for test use
        print(self.recordHash)

# test = record(123,'hi')
# test.check_variables()