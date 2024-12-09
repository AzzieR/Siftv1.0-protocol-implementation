#python3

from os import urandom
import socket, getpass, sys

#: Function that returns a random byte string of the desired size.
get_random_bytes = urandom
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

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

def encrypt_payload(hdr, payload, temp_key, nonce):
    # Create AES cipher in GCM mode
    cipher_aes = AES.new(temp_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
    cipher_aes.update(hdr)
    ciphertext, tag = cipher_aes.encrypt_and_digest(payload)
    return ciphertext, tag


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):
		self.session_key = None  # Initialize session_key to None or some default value
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
		self.rsv = b'\x00\x00'
		self.sequence_counter = 1

		##RAC added
		self.last_received_sqn = 0  # Initialize last received sequence number


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
		self.server_random = None
		
	def set_session_key(self, key):
		self.session_key = key

	def get_session_key(self):
		return self.session_key  # Retrieve the session key when needed
	
	def set_sequence_counter(self):
		self.sequence_counter += 1
	
	def get_sequence_counter(self):
		return self.sequence_counter
	
	def set_server_random(self, server_random):
		self.server_random = server_random
	
	def get_server_random(self):
		return self.server_random
	
	def decrypt_etk_with_private_key(self, encrypted_key):
		# Load the server's private key
		private_key = load_privatekey()
		# Decrypt the encrypted temporary key using RSA-OAEP
		cipher_rsa = PKCS1_OAEP.new(private_key)
		try:
			decrypted_key = cipher_rsa.decrypt(encrypted_key)
			return decrypted_key
		except Exception as e:
			print(f"Failed to decrypt ETK: {e}")
			raise SiFT_MTP_Error("Failed to decrypt ETK")

	def decrypt_and_verify_payload(self, hdr, payload, nonce, tk, mac):
    # combine rnd and sqn to generate the nonce

		# create AES cipher in GCM mode
		cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len = 12)
		cipher.update(hdr)
		try:
			# decrypt and verify the mac
			decrypted_payload = cipher.decrypt(payload)
			# Verify the MAC
			cipher.verify(mac)
			return decrypted_payload
		except ValueError as e:
			print(f"the issue: {e}")
			raise ValueError(f"MAC verification failed; {e}")
	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		
		# adding the 3 new params for the v1.0
		## Added and/or modified for v1.0
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
			msg_hdr = self.receive_bytes(self.size_msg_hdr) #TODO: Confirm the header has the right params
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)
		 #Parsing function works

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		

		current_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')  # Define current_sqn here
		print(f"Received msg sequence number: {current_sqn}")
		if current_sqn <= self.last_received_sqn:
			raise SiFT_MTP_Error('Sequence number must be greater than the last received sequence number')

		# Update the last received sequence number
		self.last_received_sqn = current_sqn
		# checks for  the sqn, rnd and rsv new fields added #TODO: Confirm with prof these checks are ok
		if parsed_msg_hdr['rsv'] != b'\x00\x00':
			raise SiFT_MTP_Error('Unknown Reserved field')
		if len(parsed_msg_hdr['rnd']) != self.size_msg_hdr_rnd:
			raise SiFT_MTP_Error('Invalid random bytes')

		# msg_len is the length of the entire msg including hdr, mac and tmp key
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		msg_type = parsed_msg_hdr['typ']
		msg_rnd = parsed_msg_hdr['rnd']
		msg_sqn = parsed_msg_hdr['sqn']
		if msg_type == self.type_login_req:
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.msg_mac_len - self.etk_size)
				lth = len(msg_body)
				mac = self.receive_bytes(msg_len - self.size_msg_hdr - lth - self.etk_size) # get mac
				etk = self.receive_bytes(msg_len - self.size_msg_hdr - lth - self.msg_mac_len) # get the etk
				tk = self.decrypt_etk_with_private_key(etk)
				self.set_session_key(tk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message etk --> ' + e.err_msg)
		
		else:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.msg_mac_len)
			lth = len(msg_body)
			mac = self.receive_bytes(msg_len - self.size_msg_hdr - lth)
			tk = self.get_session_key()
		print(f"sqn: {msg_sqn}")
		print(f"rnd: {msg_rnd}")
		print(f"the temp key: {tk.hex()}")
		print(f"the ciphertext: {msg_body}")
		print(f"the mac: {mac.hex()}")
		nonce = msg_sqn + msg_rnd
		decrypted_payload = self.decrypt_and_verify_payload(msg_hdr, msg_body, nonce, tk, mac)
		print(f"the dec payload from client: {decrypted_payload}")
		# TODO: confirm verification checks
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
			# DEBUG	
		return parsed_msg_hdr['typ'], decrypted_payload

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload): # this shuld include the tk for enc
		# build message header
		rnd_server = get_random_bytes(self.size_msg_hdr_rnd)
		sqn_server = (self.sequence_counter).to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		self.set_sequence_counter()
		msg_size = self.size_msg_hdr + len(msg_payload) + self.msg_mac_len # includes the len hdr, len epd and len mac
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn_server + rnd_server + self.rsv
		nonce = sqn_server + rnd_server
		ciphertext, mac = encrypt_payload(msg_hdr, msg_payload, self.get_session_key(), nonce)


		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(ciphertext)) + '): ')
			print(f"the cipher text sending: {ciphertext.hex()}")
			print(f'MAC ({len(mac)})')
			print(f"The actual mac from server: {mac.hex()}")
			print('------------------------------------------')

		# try to send
		try:
			self.send_bytes(msg_hdr + ciphertext + mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
