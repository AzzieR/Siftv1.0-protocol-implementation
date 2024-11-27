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
    # Generate a random cryptographic key (e.g., 32 bytes for AES-256)
    # Load the server's public key
    public_key = load_publickey(pubkeyfile)

    # Encrypt the random key using RSA-OAEP
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher.encrypt(random_key)
	# verify that the etk is 256 bytes
    # Return the encrypted key encoded in base64
    return encrypted_key

def encrypt_payload(payload, temp_key, rnd, sqn):
    # Create AES cipher in GCM mode
    cipher_aes = AES.new(temp_key, AES.MODE_GCM, nonce=rnd+sqn, mac_len=12)
    ciphertext, tag = cipher_aes.encrypt_and_digest(payload)
    return ciphertext, tag
# print(encrypt_key_with_public_key("server_pubkey.pem"))

server_pubkey_path = os.path.join(os.path.dirname(__file__), '..', '..', 'server', 'server_pubkey.pem')

class SiFT_MTP:
	def __init__(self, peer_socket):

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
		self.aes_key = get_random_bytes(16)#### typically is 16, but could be changed

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


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		## Added and/or modified for v1.0
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
		print(f"the parsed msg hdr: {parsed_msg_hdr}")
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
		mac = None
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)
		# return parsed_msg_hdr
		# print(f"the parsed msg_hdr: {parsed_msg_hdr}")

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		# actual length of the message
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		if (parsed_msg_hdr['typ']) == self.type_login_req:
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.msg_mac_len - self.etk_size)
				mac = self.receive_bytes(msg_len - self.size_msg_hdr_len - self.etk_size)
				# Load the public key from its location
		# # generate a temp key
		# 		temp_key = get_random_bytes(32)
		# 		etk = encrypt_key_with_public_key("server_pubkey.pem", temp_key)
		# 		# use the tk to encrypt the payload
		# 		sqn, rnd = parsed_msg_hdr['sqn'], parsed_msg_hdr['rnd']
		# 		ciphertext, mac = encrypt_payload(msg_body, temp_key, rnd, sqn)
		# 		print(f"Incoming login request with encrypted temp key: {etk.hex()}")
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		# TODO: IF ITS A SERVER RESPONSE TYPE: CHHECK THE SERVER RANDOM AND THE REQUEST HASH
		else:
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr) ### body including the message and mac
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# TRYING TO DECRYPT THE PAYLOAD
		# decrypted_payload = self.decrypt_payload(msg_body, mac, parsed_msg_hdr)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			if (mac):
				print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			# print('Decrypted Payload: ' + decrypted_payload)
			print('MSG RESPONSE FROM SERVER PAYLOAd: '+ str(msg_body)) # dis shld include the serverrandom sand request hash
			# should that be encrypted
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		return parsed_msg_hdr['typ'], msg_body
	
	### Added function
	def decrypt_payload(self, ciphertext, mac, parsed_msg_hdr):
		nonce = parsed_msg_hdr['rnd'] ###andom number from the header
		cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce, mac_len=self.msg_mac_len)
		cipher.update(self.create_additional_data(parsed_msg_hdr))
		try:
			decrtpyed = cipher.decrypt_and_verify(ciphertext, mac)
		except SiFT_MTP_Error:
			raise SiFT_MTP_Error('Failed to verify the MAC')
		return decrtpyed
	
	### Another added function
	def create_additional_data(self, parsed_msg_hdr):
		return (parsed_msg_hdr['ver'] + parsed_msg_hdr['typ'] +
                parsed_msg_hdr['len'] + parsed_msg_hdr['sqn'] +
                parsed_msg_hdr['rnd'] + parsed_msg_hdr['rsv'])
	


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
		print("Sending the message to the server")
		## Adding the nonce (rnd)
		rnd = get_random_bytes(self.size_msg_hdr_rnd)

		# build message
		msg_size = self.size_msg_hdr
		print(f"msg size with just header: {msg_size}")
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		sqn = (1).to_bytes(self.size_msg_hdr_sqn, byteorder='big')  ## how do we make sure that the sqn is incremented?
		rsv = b'\x00\x00'

		msg_hdr = self.msg_hdr_ver + msg_type + sqn + rnd + rsv # the header is 16 bytes which looks good
		# Generating the mac and cipher key for the msg payload
		# TODO: ADD THE ENCRYPTED TEMPKEY
		# generate a temp key
		if isLoginReq:
			temp_key = get_random_bytes(32)
			etk = encrypt_key_with_public_key(server_pubkey_path, temp_key)
			print(f"the etk right after gen: {len(etk)}")
			# use the tk to encrypt the payload
			ciphertext, mac = encrypt_payload(msg_payload, temp_key, rnd, sqn)
			print(f"the mac right after encryptio: {len(mac)}")
			print(f"Incoming login request with encrypted temp key: {etk}")
			msg_size += self.msg_mac_len + self.etk_size
		print(f"msg size with mac and etk: {msg_size}")

		msg_size += len(ciphertext)
		print(f"msg size with ciphertext: {msg_size}")

		msg_hdr = self.msg_hdr_ver + msg_type + msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big') + sqn + rnd + rsv # the header is 16 bytes which looks good

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send to server (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())

			print('BDY (' + str(len(msg_payload)) + '): ')
			print(ciphertext.hex())
			if isLoginReq:
				print('MAC (): ')
				print('MAC (' + str(len(mac)) + '): ' + mac.hex())
				print('ETK')
			print('------------------------------------------')
		# DEBUG 
		print("Entering the send bytes to the server")
		# try to send
		print(isLoginReq)
		try:
			if isLoginReq:
				print("hello in the login")
				self.send_bytes(msg_hdr + ciphertext + mac + etk) #TODO Add the encrypted temporary key
			else:
				self.send_bytes(msg_hdr + ciphertext)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

