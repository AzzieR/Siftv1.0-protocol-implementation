#python3

from os import urandom
import socket

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
		self.size_msg_hdr = 16 # the size of the header
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2	
		# Additionals for v1.0
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
		print(f"the msg_hdr = {msg_hdr}")
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		
		# adding the 3 new params for the v1.0
		## Added and/or modified for v1.0
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
		print(len(parsed_msg_hdr))	
		print(f"the parsed_msg_hdr in sever: {parsed_msg_hdr}")
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
			msg_hdr = self.receive_bytes(self.size_msg_hdr) #TODO: Confirm the header has the right params
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)
		print(f"the len of the parsed header: {len(parsed_msg_hdr)}") #Parsing function works

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		# checks for  the sqn, rnd and rsv new fields added #TODO: Confirm with prof these checks are ok
		if parsed_msg_hdr['rsv'] != b'\x00\x00':
			raise SiFT_MTP_Error('Unknown Reserved field')
		if len(parsed_msg_hdr['sqn']) != self.size_msg_hdr_sqn: # PROPER CHECK IS IF THE SEQUENCE IS UNIQUE
			raise SiFT_MTP_Error('Invalid sequence number') # how should i check to make sure the sequence number is not repeated
		if len(parsed_msg_hdr['rnd']) != self.size_msg_hdr_rnd:
			raise SiFT_MTP_Error('Invalid random bytes')

		# msg_len is the length of the entire msg including hdr, mac and tmp key
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		msg_type = parsed_msg_hdr['typ']
		if msg_type == self.type_login_req:
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.msg_mac_len - self.etk_size)
				print(f"MSG LEN: {msg_len}")
				print(f"acc msg body len: {len(msg_body)}")
				print("hello bfr mac")
				lth = len(msg_body)
				print(lth)
				print(self.size_msg_hdr)
				print(self.etk_size)
				mac = self.receive_bytes(msg_len - self.size_msg_hdr - lth - self.etk_size) # get mac
				print(f"left: {msg_len - lth - self.size_msg_hdr - self.etk_size}")
				print("hello after mac")
				print(mac)
				etk = self.receive_bytes(msg_len - self.size_msg_hdr - lth - self.msg_mac_len) # get the etk
				print(etk)
				print("hello after etk")
				print(f"the mac received: {len(mac)}")
				print(f"the etk received after: {len(etk)}")
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		else:
			try:
				print(f"MSG LEN: {msg_len}")
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		# TODO: confirm verification checks
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 
		if msg_type == self.type_login_req:
			if len(msg_body) != msg_len - self.size_msg_hdr - self.etk_size - self.msg_mac_len: #TODO Update when mac and etk is added
				raise SiFT_MTP_Error('Incomplete message body reveived')
			print("the message body received is complete")
			return parsed_msg_hdr['typ'], parsed_msg_hdr['sqn'], parsed_msg_hdr['rnd'], parsed_msg_hdr['rsv'], msg_body, mac, etk
		else:
			if len(msg_body) != msg_len - self.size_msg_hdr: #TODO Update when mac and etk is added
				raise SiFT_MTP_Error('Incomplete message body reveived')
			return parsed_msg_hdr['typ'], msg_body
		# adding the msg rnd, sqn and rsv


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	# added the new header params to the send_msg
	def send_msg(self, msg_type, msg_sqn, msg_rnd, msg_rsv, msg_payload):
		
		# build message
		msg_size = self.size_msg_hdr + len(msg_payload)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + msg_rsv
		# TODO
		# Include the msg tkey and mac if login request type
		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_payload)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

#: Function that returns a random byte string of the desired size.
get_random_bytes = urandom
