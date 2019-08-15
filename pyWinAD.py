import os
import requests
import json
import base64
import socket
import hashlib
import random
import string
import subprocess
import openstack
from Crypto import Random
from Crypto.Cipher import AES

class WinADClient():

    aes_key = "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4="

    # Defaults you to an unauthorized credential, with an External role. This allows you to use none of the methods.
    #   --> External is to manage a VM externally
    #   --> Internal is to manage a VM internally
    #
    # External build:
    #    import clo-pyWinAD as pyWinAD
    #    prov = pyWinAD.WinADClient(creds = <Authorized_API_Credentials>)
    #
    # Internal build:
    #   import clo-pyWinAD as pyWinAD
    #   prov = pyWinAD.WinADClient(role = "Internal")

    def __init__(self, creds="unauthorized_base_user", base_url= "http://10.112.43.202/api/", role="External"):
        self.encryption_key = self.recoverEncKey()
        # You are the VM itself
        if role.lower() == "internal" :
            self.role = "Internal"
            self.domain_name = os.getenv('COMPUTERNAME')
        # You are the provisioner 
        else:
            self.role = "External"
            self.domain_name = None
        self.token = self.encrypt(creds)
        self.base_url = base_url
        self.headers = {}
        self.headers['Content-Type'] = "application/json; charset=UTF-8"
        self.headers['Authorization'] = self.token


    #******************** Can be used by either **************************


    def __post(self, func, data):
        return requests.request("POST", url=self.base_url + func, data=data, headers=self.headers)


    def isExternal(self):
        return (self.role == "External")


    def setAuth(self, cred):
        self.headers['Authorization'] = cred

    def setDomain(self, domain_name):
        self.domain_name = domain_name
        return "Domain name updated within client instance."


    def joinMachine(self, ad_domain):
        # we only have the API configured for these ad domains
        if ad_domain in ["hszq, hsz"]:
            # attempts to enforce naming convention defined by changeDomain()
            if "-us-e1" not in self.domain_name :
                payload = self.buildPayload({"name": self.domain_name, "domain": ad_domain, "groups": "NO_GROUPS"})
                response = self.__post("join.php", payload)
                return response.text+"\nIf Internal, you need to make sure that you have set authorized API credentials."
        return "Error. Must use 'setDomain()' (external) to set the VM name - or 'changeDomain()' (internal) to rename the VM and list it in DNS."


    def logToDns(self, domain, raw_addy, dnsCred=None):
        if(dnsCred):
            self.setAuth(self.encrypt(dnsCred))
        payload = self.buildPayload({"name": domain, "raw_ip": raw_addy})
        response = self.__post("logToDNS.php", payload)
        self.setAuth(self.token)
        return response.text


    def setAPICred(self, creds):
        self.token = self.encrypt(creds)
        self.setAuth(self.token)
        return("Credential set.")

    
    def buildPayload(self, data):
        payload_array={}
        payload_array["data"] = data
        payload = json.dumps(payload_array)
        return payload


    # this is where we would have it pull the AES key from Vault
    def recoverEncKey(self):
        return base64.urlsafe_b64decode(self.aes_key)

    
    def encrypt(self, bare_key):
        aes_key = self.encryption_key
        chunk_size = AES.block_size
        offset = 0
        encrypted = b''
        end_loop = False
        while not end_loop:
            chunk = bare_key[offset:offset + chunk_size]
            # padding
            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk = chunk + (AES.block_size - len(chunk) % AES.block_size) * " "
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted += (iv + cipher.encrypt(chunk))
            offset += chunk_size
        return (base64.urlsafe_b64encode(encrypted)).decode('utf-8')


    #******************** External to VM Use ************************************


    def addAPICredential(self, new_creds):
        if self.isExternal() :
            enc_creds = self.encrypt(new_creds)
            payload = self.buildPayload({"new_cred": enc_creds})
            response = self.__post("addCreds.php", payload)
            return response.text
        return "ERR: Using external method with internal instance."


    def changeEncryptionKey(self, key=None):
        if self.isExternal() :
            if not key:
                key = ''.join(random.choice(string.ascii_lowercase) for i in range(30))
            aes_key = hashlib.sha256(key.encode()).digest()
            # Some vault method here to update vault variable
            return "Feature unsupported until Progressive gets Vault"
        else:
            #return "ERR: Using external method with internal instance."
            return "Feature unsupported until Progressive gets Vault"


    #******************** Internal to VM Use ************************************


    def genDomain(self):
        if not self.isExternal() :
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            raw_addy = s.getsockname()[0]
            s.close()
            pieces = raw_addy.split(".")
            new_name = ""
            i = 0
            while i < len(pieces)-1:
                new_name += pieces[i]+"-"
                i+=1
            new_name += pieces[i]+"-us-e1"
            return [new_name, raw_addy]
        else:
            return "ERR: Using internal method with external instance. Be aware that 'setDomain(<domain_name>)' does not change the domain of the VM internally, or in DNS listing."


    def runDomain(self, old_domain, new_domain=None):
        if not self.isExternal() :
            if not new_domain:
                new_domain = self.domain_name
            cmds = "powershell $passwd = ConvertTo-SecureString 'WDd-2w19-d94!' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential ('.\lanadmin', $passwd); Rename-Computer -ComputerName "+old_domain+" -NewName "+new_domain+" -DomainCredential $cred -Force -Restart; exit;"
            out = subprocess.check_output(cmds.split(" "), shell=True)
            if "exception" not in out.decode('utf-8').lower() :
                return "ur gud"
            return "ERR: Failed to change domain internally."
        else:
            return "ERR: Using internal method with external instance."


    def updateMetadata(self):
        if not self.isExternal() :
            try:
                stack_conn = openstack.connect(
                    auth_url = os.environ['OS_AUTH_URL'],
                    project_name = os.environ['OS_PROJECT'],
                    username = os.environ['OS_USER_NAME'],
                    password = os.environ['OS_PASSWORD'],
                    region_name = os.environ['OS_REGION'],
                    project_domain_name = os.environ['OS_DOMAIN'],
                    user_domain_name = os.environ['OS_DOMAIN'],
                    app_name = 'examples',
                    app_version = '1.0',
                )
                # ask rick about instance ID, is it just uuid? is there a way to do this without using a curl command...
                response = requests.get('http://169.254.169.254/openstack/2017-02-22/meta_data.json')
                son = json.loads(response.text)
                #stack_conn.compute.set_server_metadata(son["uuid"], AD_COMPUTERNAME=self.domain_name)
                #stack_conn.compute.set_server_metadata(son["uuid"], MACHINE_TYPE="WINDOWS")
                stack_conn.set_server_metadata(son["uuid"], AD_COMPUTERNAME=self.domain_name)
                stack_conn.set_server_metadata(son["uuid"], MACHINE_TYPE="WINDOWS")
                return "Openstack metadata set successfully."
            except IndexError:
                return "ERR: Unable to configure OpenStack API connection due to unset environmental variables."
            except Exception as e:
                return "ERR: Unable to update metadata. Errored on: "+str(e)
        return "ERR: Using internal method with external instance."


    # This method does everything to change domain and enter DNS listing. This can only run within the actual VM.
    def changeDomain(self, dnsCred=None):
        if not self.isExternal() : 
            machine_info = self.genDomain()
            old_name = self.domain_name
            new_name = machine_info[0]
            raw_addy = machine_info[1]
            if(new_name == old_name):
                return "Already set."
            self.setDomain(new_name)
            resp = self.logToDns(new_name, raw_addy, dnsCred)
            if "ERR" not in resp:
                resp = self.updateMetadata()
                # this command will restart machine
                print("*****warning machine will restart if command is successful*****")
                response = self.runDomain(old_name)
                return response
            else:
                return "Failed to log DNS record with: "+resp
        else:
            return "ERR: Using internal method with external instance. Use 'setDomain(<domain_name>)' to update the domain name that this instance is referring to."
        