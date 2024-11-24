from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time, sys, os, getpass
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def load_privatekey():
    privkeyfile = input('Enter the full path to the private key file: ')
    passphrase = getpass.getpass('Enter passphrase for private key: ')
    with open(privkeyfile, 'rb') as f:
        privkeystr = f.read()
    try:
        return RSA.import_key(privkeystr, passphrase=passphrase)
    except ValueError as e:
        print(f'Error: Cannot import private key from file {privkeyfile} : {e}')
        sys.exit(1)

def decrypt_etk_with_private_key(encrypted_key):
    # Load the server's private key
    private_key = load_privatekey()

    # Decrypt the encrypted temporary key using RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)

    return decrypted_key

def decrypt_and_verify_payload(payload, tk, rnd, sqn, mac):
    # combine rnd and sqn to generate the nonce
    nonce = rnd + sqn

    # create AES cipher in GCM mode
    cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len = 12)
    try:
        # decrypt and verify the mac
        c_mac = cipher.verify(mac)
    except ValueError:
        raise ValueError("MAC verification failed")

    try:
        decrypted_payload = cipher.decrypt(payload)
        return decrypt_and_verify_payload
    except ValueError:
        raise ValueError("Failed to decrypt the payload")
class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    # the login request: does it include the timestamp and client_random from the client same aas the login_request?
    def build_login_req(self, login_req_struct):
        login_req_str = login_req_struct['timestamp']
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + login_req_struct['client_random'] 
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):
# TODO ADD DECRYPTION
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = login_req_fields[0]
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = login_req_fields[3]
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash'].hex() + login_res_struct['server_random'].hex()
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0]) # should be converted to a string
        # add the server random to the res_struct
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[0]) # confirm that this is a hex value and shoud be converted to a string
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')
        print("entered the server's handling of login")
        # trying to receive a login request
        try:
            msg_type, msg_sqn, msg_rnd, msg_rsv, msg_payload, mac, etk = self.mtp.receive_msg() # add the new patameters
            # TODO add the mac and the etk
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)
        print("successfully captured all needed params")
        # DEBUG 
        if self.DEBUG:
            print(f"Incoming: {msg_payload}")
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            #print(msg_payload[:max(512, len(msg_payload))].decode('utf-8')) # the payload is encrypted here so cannot be decoded so should take out
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')
        
        # TODO: HAVE CHECKS FOR THE OTHER NEW FIELDS INCLUDED IN THE HEADER

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()
        server_random = get_random_bytes(16) #added the server random needed for the permanent key
        # TODO VERIFY THE args
        # TODO: Dec the payload
        # decrypt the etk using server's private key and RSA-OAEP in enc mode
        # get the file path
        # privkeyfile_path = os.path.join(os.path.dirname(__file__), '..', 'server_keypair.pem')
        tk = decrypt_etk_with_private_key(etk)
        print(f"the tk: {tk}")
        login_req_struct = self.parse_login_req(msg_payload)

        # TODO ADD VERIFICATION FRO THE CLIENT RANDOM AND TIMESTAMP
        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        # adding the server random bytes to the server login response
        server_random = get_random_bytes(16)
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = server_random
        # TODO: Should the login responses be encrypted?
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload from server login (' + str(len(msg_payload)) + '):') # this returns an error because for some reason the message is just 7 bytes and not 9
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        # TODO: Shou;d we send the client's own details back to the client in this send_msg
        # TODO: The send should inclde the login response tye and msg_payload
        try: # should the login response include the header?
            self.mtp.send_msg(self.mtp.type_login_res, msg_sqn, msg_rnd, msg_rsv, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, timestamp, username, password, client_random):

        # building a login request
        login_req_struct = {}
        login_req_struct['timestamp'] = timestamp
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = client_random
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload from server: (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)
    
        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

