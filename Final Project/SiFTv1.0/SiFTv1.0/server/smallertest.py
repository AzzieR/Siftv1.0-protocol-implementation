##Encrypt
#python3

import os
import socket
## Added imports
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys

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
    print(f"pub: {public_key.export_key().decode("utf-8")}")
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher.encrypt(random_key)
    # print(f"enc: {encrypted_key}")
    return encrypted_key

def encrypt_payload(payload, temp_key, rnd, sqn):
    # Create AES cipher in GCM mode
    cipher_aes = AES.new(temp_key, AES.MODE_GCM, nonce=rnd+sqn)
    ciphertext, tag = cipher_aes.encrypt_and_digest(payload)
    return ciphertext, tag

server_pubkey_path = os.path.join(os.path.dirname(__file__), '..', '..', 'server', 'server_pubkey.pem')

def load_privatekey():
    privkeyfile = input("Enter the full path to the private key file: ")
    try:
        # Step 1: Load the private key
        with open(privkeyfile, 'rb') as f:
            privkey_data = f.read()
        			
        privkey_data = RSA.import_key(privkey_data, passphrase="2003")
        print("Private key successfully loaded.", privkey_data)
        return privkey_data

    except ValueError as e:
        if "Padding" in str(e):
            print(f"Error: Cannot import private key from file {privkey_data}. The key file may be corrupted or improperly formatted (PADDING ERROR). Ensure the file is correct.")
        elif "password" in str(e).lower():
            print(f"Error: Incorrect passphrase provided for private key file {privkey_data}. Please try again with the correct passphrase.")
        else:
            print(f"Error: Cannot import private key from file {privkey_data}. Ensure the passphrase is correct and the key file is properly formatted.\nDetails: {e}")
        sys.exit(1)

    except FileNotFoundError:
        print(f"Error: Private key file {privkey_data} not found. Please check the file path and try again.")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error occurred while loading private key from file {privkey_data}. Please verify the file and passphrase.\nDetails: {e}")
        sys.exit(1)




def decrypt_etk_with_private_key(encrypted_key):
    # Load the server's private key
    private_key = load_privatekey()

    # Decrypt the encrypted temporary key using RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)

    return decrypted_key




##TESTTT
def test_encryption_decryption():
    server_pubkey_path = os.path.join(os.path.dirname(__file__), 'server_pubkey.pem')
    # print(server_pubkey_path)
    test_key = get_random_bytes(32)
    print(f"testk: {test_key}")
    etk = encrypt_key_with_public_key(server_pubkey_path, test_key)
    print(f"etk {etk}")
    priKey = load_privatekey()
    print(f'prikey: {priKey.export_key().decode("utf-8")}')
    act_key = decrypt_etk_with_private_key(etk)
    print(f'acc key: {act_key}')
    return acckey


acckey = b'\x8d\x85[\xf9=\x8ba7\x1d3x\xb4'
testk: b'\x8d\x85[\xf9=\x8ba7\x1d3x\xb4'

# Call the test function
test_encryption_decryption()
tmp_key = b'\x0c\xc8\xa2\xf4\xd8\xd2\xea_\x06\xba\xd1\n0\x95c\x9a\xb8TO\xb7\xc1\xc6\\\xfd\xc7\xdb\xc8Y4\xa0\xfb\xaa'
etk_cli= b'\x96*\'\x90\xe7h\xc2sq\xdc(O\xfb\xc6\xbd\xc2=\'\xd7B\xfb\x0f\xdb\x9d(\x11&\xa0F\xa3e\x0b\rG\xfcr2\x7f\x06\xbdg\xf9\xfay\xc8\'K\xf3\x96\x95C\x8b\x96KOa\xc1m\x80\x94q7/\x81\xe6\xbc\x8d\xcev\xe6\xaf\x85\x9a\x8fB\xa5\xf1\xd5YE\xa6\xdci\xa3S\xc3cf\x04\xdc\xad\x8br\xf6{\xef\x95\xec\x1d\xaa\x1bk\x93\xf1.\x97\x90\xc3(R\xbb)\x1d\x07iD\xf1d_\x06k\x89\xbe9->\xdd\xcbiC\xb6v\xe5\x9b\xc1`R\xf9%^G\xec\x9dN\xc0<8\x0b5\x00B\xb1\x97\x1e\xd0\xb6\xc7sB\xe2\x87\\\x9co\xc1\xf0l;|\x8d<\x0b\xb1a7\xc8\xb1!\x10\xe4n\xc6\xdf\xc5\x1f\xb9q5\x98\x86\x1b\xf8\xb6\xb0W\x8a\xe3\x96\xd7`4\xc2.\t\xad\xf0\xb6\xbe\xd3\xb7\x81"&[\x1dN\x8ahs\x9b\xbaF\x14\xa0\x8f\xfd\x9d1\xafh\xd6l\xf86PD\x8c\xae\x07\x80&?\x01\xd4\x9c\xd1U:I\xb9h\x99\x98\x83}j'

mac_cli = "a1e0fb07ecf890e725b6cdeac873e45a"
mac_ser = "a1e0fb07ecf890e725b6cdea"

tk_s = b'\x03-\xeeFLQ\xcb\xe8\x9e\xeb\xb6"\xdaE\x8d\x0b\xc5\xf6\x80;C?\x80\xd4\xde\xcd6~\x1e\x02\x86\xa5'







 