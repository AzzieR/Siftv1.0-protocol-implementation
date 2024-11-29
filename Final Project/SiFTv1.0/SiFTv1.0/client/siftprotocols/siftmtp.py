#python3

import os
import socket
## Added imports
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64, sys

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

""" Loading the server's public key from its file"""
def load_publickey(pubkeyfile):
	with open(pubkeyfile, 'rb') as f:
		pubkeystr = f.read()
	try:
		return RSA.import_key(pubkeystr)
	except ValueError:
		print('Error: Cannot import public key from file ' + pubkeyfile)
		sys.exit(1)

""" Encryption of the server's public key with the random bytes temp key"""
def encrypt_key_with_public_key(pubkeyfile, random_key):
    public_key = load_publickey(pubkeyfile)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher.encrypt(random_key)
    return encrypted_key

def encrypt_payload(payload, temp_key, rnd, sqn):
    cipher_aes = AES.new(temp_key, AES.MODE_GCM, nonce=rnd+sqn, mac_len=12)
    ciphertext, tag = cipher_aes.encrypt_and_digest(payload)
    return ciphertext, tag

server_pubkey_path = os.path.join(os.path.dirname(__file__), '..', '..', 'server', 'server_pubkey.pem')

class SiFT_MTP:
	def __init__(self, peer_socket):
		self.session_key = None  # Initialize session_key to None or some default value

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2

		## Additionals for v1.0
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.msg_mac_len = 12
		self.etk_size = 256
		self.sequence_counter = 1

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.client_random = None

	def set_session_key(self, key):
		self.session_key = key
	def get_session_key(self):
		return self.session_key  # Retrieve the session key when needed
	
	def set_sequence_counter(self):
		self.sequence_counter += 1
	
	def get_sequence_counter(self):
		return self.sequence_counter
	
	def set_client_random(self, client_random):
		self.client_random = client_random
	
	def get_client_random(self):
		return self.client_random
	
	def decrypt_payload(self, ciphertext, key, mac, sqn, rnd): # from server to client
		print(f'the dec key: {key}')
		nonce = rnd + sqn
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.msg_mac_len)
		try:
			decrypted = cipher.decrypt(ciphertext)
			print(f"the decrypted: {decrypted}")
			cipher.verify(mac)
		except ValueError as e:
			raise SiFT_MTP_Error(f'Failed to verify the MAC: {e}')
		return decrypted
	
	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		# actual length of the message
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		isLoginRes = parsed_msg_hdr['typ'] == self.type_login_res

		try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.msg_mac_len)
				lth = len(msg_body)
				mac = self.receive_bytes(msg_len - self.size_msg_hdr - lth)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		            
        # TODO: Decrypt this payload
		msg_sqn = parsed_msg_hdr['sqn']
		msg_rnd = parsed_msg_hdr['rnd']
		# if isLoginRes:
		decrypted_payload = self.decrypt_payload(msg_body, self.get_session_key(), mac, msg_sqn, msg_rnd)
		print(f"the server's response: {decrypted_payload}")

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(decrypted_payload)) + '): ')
			print(decrypted_payload.hex)
			if (mac):
				print(f"Mac bytes: {mac}")
				print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			print('------------------------------------------')
		
		# DEBUG 
		if len(decrypted_payload) != msg_len - self.size_msg_hdr - self.msg_mac_len: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		return parsed_msg_hdr['typ'], decrypted_payload
	
	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send) # it fails in the sending place because somehow the header and the message payload are incorect
			print("successfully sent")
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		isLoginReq = msg_type == self.type_login_req
		ciphertext = msg_payload
		msg_size = 0
		## Adding the nonce (rnd)
		rnd = get_random_bytes(self.size_msg_hdr_rnd)
		# build message
		sqn = self.sequence_counter.to_bytes(self.size_msg_hdr_sqn, byteorder='big') # but confirm how we verify the sequence counter though.
		self.set_sequence_counter()
		rsv = b'\x00\x00'
		if isLoginReq:
			temp_key = get_random_bytes(32)
			etk = encrypt_key_with_public_key(server_pubkey_path, temp_key)
			self.set_session_key(temp_key)
			msg_size = self.etk_size
		else:
			temp_key = self.get_session_key()
		ciphertext, mac = encrypt_payload(msg_payload, temp_key, rnd, sqn)
		msg_size += self.size_msg_hdr + len(ciphertext) + self.msg_mac_len 
		msg_hdr = self.msg_hdr_ver + msg_type + msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big') + sqn + rnd + rsv # the header is 16 bytes which looks good

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send to server (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(ciphertext)) + '): ')
			print(f'MAC ({len(mac)})')
			if isLoginReq:
				print(f'ETK ({len(etk)})')
			print('------------------------------------------')
		# DEBUG 
		try:
			if isLoginReq:
				self.send_bytes(msg_hdr + ciphertext + mac + etk)
			else:
				self.send_bytes(msg_hdr + ciphertext + mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)