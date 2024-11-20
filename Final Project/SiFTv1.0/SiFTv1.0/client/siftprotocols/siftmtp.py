#python3

import os
import socket
## Added imports
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

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

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		# TODO: IF ITS A SERVER RESPONSE TYPE: CHHECK THE SERVER RANDOM AND THE REQUEST HASH
		try:
			msg_body_mac = self.receive_bytes(msg_len - self.size_msg_hdr) ### body including the message and mac
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		msg_body, mac = msg_body_mac[:-self.msg_mac_len], msg_body_mac[-self.msg_mac_len:] ### separate the message body and the mac

		# ## Added for handling logging in
		# if parsed_msg_hdr['typ'] == self.type_login_req:
		# 	encry_temp_key_len = 32 ## ?? what is etk length anyways
		# 	encry_temp_key = msg_body[-encry_temp_key_len:]
		# 	print(f"Incoming login request with encrypted temp key: {encry_temp_key.hex()}")

		# # decrypted_payload = self.decrypt_payload(msg_body,mac,parsed_msg_hdr)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			# print('Decrypted Payload: ' + decrypted_payload)
			print('MSG RESPONSE FROM SERVER PAYLOAd: '+msg_body) # dis shld include the serverrandom sand request hash
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
		print("Sending the message to the server")
		## Adding the nonce (rnd)
		rnd = get_random_bytes(self.size_msg_hdr_rnd)

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		sqn = (1).to_bytes(self.size_msg_hdr_sqn, byteorder='big')  ## how do we make sure that the sqn is incremented?
		rsv = b'\x00\x00'

		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn + rnd + rsv # the header is 16 bytes which looks good
		# Generating the mac and cipher key for the msg payload
		# TODO: ADD THE ENCRYPTED TEMPKEY
		cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=rnd, mac_len=self.msg_mac_len)
		cipher.update(msg_hdr)
		ciphertext, mac = cipher.encrypt_and_digest(msg_payload)
		# TODO: Add the encrypted temporary key here

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('MAC (): ')
			# print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			print('------------------------------------------')
		# DEBUG 
		print("Entering the send bytes to the server")
		# try to send
		mac = os.urandom(12)
		print(mac.hex())
		try:
			self.send_bytes(msg_hdr + msg_payload + mac) #TODO Add the encrypted temporary key
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


