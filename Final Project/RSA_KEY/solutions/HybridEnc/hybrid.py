import sys, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

# -------------
# configuration
# -------------

operation = 'enc'  # possibilities: kpg, enc, dec
pubkeyfile = 'test_pubkey.pem'
privkeyfile = 'test_keypair.pem'
inputfile = 'test_plaintext1.txt'
outputfile = 'test.txt'
sign = True

# -----
# utils
# -----

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

# -------------------
# key pair generation
# -------------------

if operation == 'kpg': 
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey(), pubkeyfile)
    save_keypair(keypair, privkeyfile)
    print('Done.')

# ----------
# encryption
# ----------

elif operation == 'enc': 
    print('Encrypting...')

    # load the public key from the public key file and 
    # create an RSA cipher object
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    # read the plaintext from the input file
    with open(inputfile, 'rb') as f: 
        plaintext = f.read()

    # apply PKCS7 padding on the plaintext
    padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
	
    # generate a random symmetric key 
    # and create an AES cipher object
    symkey = Random.get_random_bytes(32) # we use a 256 bit (32 byte) AES key
    AEScipher = AES.new(symkey, AES.MODE_CBC)
    iv = AEScipher.iv

    # encrypt the padded plaintext with the AES cipher
    ciphertext = AEScipher.encrypt(padded_plaintext)

    #encrypt the AES key with the RSA cipher
    encsymkey = RSAcipher.encrypt(symkey)  

    # compute signature if needed
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = PKCS1_PSS.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    # write out the encrypted AES key, the IV, the ciphertext, and the signature
    with open(outputfile, 'wb') as f:
        f.write(newline(b'--- ENCRYPTED AES KEY ---'))
        f.write(newline(b64encode(encsymkey)))
        f.write(newline(b'--- IV FOR CBC MODE ---'))
        f.write(newline(b64encode(iv)))
        f.write(newline(b'--- CIPHERTEXT ---'))
        f.write(newline(b64encode(ciphertext)))
        if sign:
            f.write(newline(b'--- SIGNATURE ---'))
            f.write(newline(b64encode(signature)))

    print('Done.')

# ----------
# decryption
# ----------

elif operation == 'dec':
    print('Decrypting...')

    # read and parse the input
    encsymkey = b''
    iv = b''
    ciphertext = b''

    with open(inputfile, 'rb') as f:        
        sep = f.readline()
        while sep:
            data = f.readline()
            data = data[:-1]   # removing \n from the end
            sep = sep[:-1]     # removing \n from the end

            if sep == b'--- ENCRYPTED AES KEY ---':
                encsymkey = b64decode(data)
            elif sep == b'--- IV FOR CBC MODE ---':
                iv = b64decode(data)
            elif sep == b'--- CIPHERTEXT ---':
                ciphertext = b64decode(data)
            elif sep == b'--- SIGNATURE ---':
                signature = b64decode(data)
                sign = True

            sep = f.readline()

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of input file ' + inputfile)
        sys.exit(1)

    if sign and (not pubkeyfile):
        print('Error: Public key file is missing for  ' + inputfile)
        sys.exit(1)

    # verify signature if needed
    if sign:
        pubkey = load_publickey(pubkeyfile)
        verifier = PKCS1_PSS.new(pubkey)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        if verifier.verify(hashfn, signature):
            print('Signature verification is successful.')
        else:
            print('Signature verification is failed.')
            yn = input('Do you want to continue (y/n)? ')
            if yn != 'y': 
                sys.exit(1)

    # load the private key from the private key file and 
    # create the RSA cipher object
    keypair = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(keypair)

    #decrypt the AES key 
    try:
        symkey = RSAcipher.decrypt(encsymkey)  
    except ValueError:
        print('Error: Decryption of the AES key failed.')
        sys.exit(1)
    
    # create the AES cipher object
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)	
	
    # decrypt the ciphertext and remove padding
    try:
        padded_plaintext = AEScipher.decrypt(ciphertext)
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='pkcs7')
    except ValueError:
        print('Error: Decryption of the ciphertext failed.')
        sys.exit(1)

	
    # write out the plaintext into the output file
    with open(outputfile, 'wb') as f:
        f.write(plaintext)
	
    print('Done.')
