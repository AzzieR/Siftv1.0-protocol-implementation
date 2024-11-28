#python3

import os
import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Cipher import AES


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


    # builds a login request from a dictionary including timestamp and client random
    def build_login_req(self, login_req_struct):
        # the time stamp and client random should be added here
        time_stamp = int(time.time() * 1000)
        client_random = str(os.urandom(16))
        login_req_str = str(time_stamp)
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + client_random
        print(f"the login: {login_req_str}")
        print(f"the login req encode: {login_req_str.encode(self.coding)}")
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['username'] = login_req_fields[0]
        login_req_struct['password'] = login_req_fields[1]
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex() 
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        print(f"in parse: {login_res}")
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # is it the response of the login from the server
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):
        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        msg_payload = self.build_login_req(login_req_struct)
        print(f"the msg payload: {msg_payload}")
        # computing hash of request payload bfr enc
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()
        # DEBUG 
        if self.DEBUG: # TODO Should we take out this print statements
            print('Outgoing payload from client: (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)



        print(f"the req hash of the login req cli: {request_hash.hex()}")

        # trying to receive a login response
        try:
            # this is supposed to print something but nothing gets printed out
            msg_type, msg_sqn, msg_rnd, msg_payload, mac = self.mtp.receive_msg()
 
            if msg_type != self.mtp.type_login_res:
                raise SiFT_LOGIN_Error(f'Login request expected, but received something else {msg_type}')
            
            # TODO: Decrypt this payload
            decrypted_payload = self.decrypt_payload(msg_payload, self.mtp.get_session_key(), mac, msg_sqn, msg_rnd)
            print(f"the server's response: {decrypted_payload}")
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(decrypted_payload)) + '):')
            print(decrypted_payload[:max(512, len(decrypted_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(decrypted_payload)
        print(f"the login_res_struct: {login_res_struct}")
        print(f"the req has from the server: {login_res_struct['request_hash'].hex()}")
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
	### Added function
    def decrypt_payload(self, ciphertext, key, mac, sqn, rnd): # from server to client
        print(f'the dec key: {key}')
        nonce = rnd + sqn
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.mtp.msg_mac_len)
        try:
            decrtpyed = cipher.decrypt(ciphertext)
            print(f"the decrypted: {decrtpyed}")
            cipher.verify(mac)
        except ValueError as e:
            raise SiFT_MTP_Error(f'Failed to verify the MAC: {e}')
        return decrtpyed

# 741c8ec0af102fba41251536ce010f88f576044684ca22b02d37d2441940a8c6
# 741c8ec0af102fba41251536ce010f88f576044684ca22b02d37d2441940a8c6

# f4845e53c02b10fc3fe58186ddab0b90f7a65b8c8618be3a780fcf03e4a61f85