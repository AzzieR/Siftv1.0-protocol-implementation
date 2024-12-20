from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time, sys, os, getpass
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from collections import defaultdict
import hmac
import hashlib


    
class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

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
    except Exception as e:
        print(f'Unexpected error: {e}')
        sys.exit(1)

def decrypt_etk_with_private_key(encrypted_key):
    # Load the server's private key
    private_key = load_privatekey()
    print(f"the private key: {private_key}")
    # Decrypt the encrypted temporary key using RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key)
    try:
        decrypted_key = cipher_rsa.decrypt(encrypted_key)
        return decrypted_key
    except Exception as e:
        print(f"Failed to decrypt ETK: {e}")
        raise SiFT_LOGIN_Error("Failed to decrypt ETK")

def decrypt_and_verify_payload(payload, rnd, sqn, tk, mac):
    # combine rnd and sqn to generate the nonce
    nonce = rnd + sqn

    # create AES cipher in GCM mode
    cipher = AES.new(tk, AES.MODE_GCM, nonce=rnd+sqn, mac_len = 12)
    try:
        # decrypt and verify the mac
        decrypted_payload = cipher.decrypt(payload)
        
        # Verify the MAC
        cipher.verify(mac)
        print(f'the dec payload: {decrypted_payload}')
        return decrypted_payload
    except ValueError as e:
        print(f"the issue: {e}")
        raise ValueError(f"MAC verification failed; {e}")

seen_timestamps = set()

# validates the freshness of the timestamp
def validate_timestamp(received_timestamp, window=200):
    current_time = int(time.time() * 1000)  # Milliseconds
    window_ms = window * 1000
    received_timestamp = int(received_timestamp)  # Convert to integer
    if current_time - window_ms <= received_timestamp <= current_time + window_ms:
        return True
    else:
        print(f"Timestamp outside the valid window: {received_timestamp} (current time: {current_time})")
        return False

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


    # CHANGE THIS PROBABLY TO THE OLD VERSION
    def parse_login_req(self, login_req):
        # TODO ADD DECRYPTION
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        ## Error check
        if len(login_req_fields) != 4:
            raise SiFT_LOGIN_Error('Invalid login request format')
        login_req_struct = {}
        login_req_struct['timestamp'] = login_req_fields[0]
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = login_req_fields[3]
        print(f"the login req struct: {login_req_struct}")
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
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1]) # confirm that this is a hex value and shoud be converted to a string
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False
    
    def load_final_key(final_key_file):
        passphrase = getpass.getpass('Enter the password the final key (server-side): ')  
        try:
            with open(final_key_file, 'rb') as f:
                final_key = f.read()
            return final_key
        except Exception as e:
            print(f"Error loading final key: {e}")

    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')
        print("entered the server's handling of login")
        # trying to receive a login request
        try:
            msg_ver ,msg_type, msg_len, msg_sqn, msg_rnd, msg_rsv, msg_payload, mac, etk = self.mtp.receive_msg() # add the new patameters
            print(f"the mac after handling: {mac}")
            # TODO add the mac and the etk

            if msg_type != self.mtp.type_login_req:
                raise SiFT_LOGIN_Error('Login request expected, but received something else')
            
            tk = decrypt_etk_with_private_key(etk)
            decrypted_payload = decrypt_and_verify_payload(msg_payload, msg_rnd, msg_sqn, tk, mac)
            login_req_struct = self.parse_login_req(decrypted_payload)

            request_hash = SHA256.new(data=msg_payload).digest()

            # Validate the client-provided request hash if present
            client_request_hash = login_req_struct.get('request_hash')  # Include in the request
            if client_request_hash and client_request_hash != request_hash:
                raise SiFT_LOGIN_Error('Request hash mismatch')

            if login_req_struct['username'] not in self.server_users:
                raise SiFT_LOGIN_Error('User not found')
            
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password incorrect')
            
            received_timestamp = login_req_struct['timestamp']
            if not validate_timestamp(received_timestamp):
                raise SiFT_LOGIN_Error('Timestamp validation failed: potential replay attack or clock mismatch')
            
            # final_key = self.generate_final_key(server_random, mac)
            # print(f"Final key: {final_key.hex()}")
           
            server_random = get_random_bytes(16)

            login_res_struct = {
                'request_hash': request_hash,
                'server_random': server_random,
            }
            msg_res_payload = self.build_login_res(login_res_struct)
            # sqn should be different
            """
            
            """
            
            # msg_hdr = ver+leb+ty:res+sqn+rnd+sv+
            self.mtp.send_msg(self.mtp.type_login_res, msg_res_payload)

        except Exception as e:
            print(f"Error occurred during login handling: {e}")
            raise SiFT_LOGIN_Error('Login handling failed')

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 
        return login_req_struct['username'] 


    # handles login process (to be used by the client)
    def handle_login_client(self, timestamp, username, password, client_random, server_random): ## edited to include the server random

        # building a login request
        login_req_struct = {}
        login_req_struct['timestamp'] = timestamp
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = client_random
        login_req_struct['server_random'] = server_random
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload from server: (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        msg_rnd = self.mtp.get_random()
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload, client_random, msg_rnd ,msg_payload )
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new(data=msg_payload)
        # hash_fn.update(msg_payload)
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

