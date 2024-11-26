#python3

import os, sys, threading, socket, getpass
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error

from Crypto.PublicKey import RSA
"""
Server's RSA Implementation
"""
def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM', passphrase =None))

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
        f.write(keypair.export_key(format='PEM', passphrase=None))

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def generate_keypair(pubkeyfile, privkeyfile):
    if os.path.exists(pubkeyfile) and os.path.exists(privkeyfile):
        print('Key pair already exists. Skipping key generation.')
        return

    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey(), pubkeyfile)
    save_keypair(keypair, privkeyfile)
    print('Done.')

# Example usage
pubkeyfile = 'server_pubkey.pem'
privkeyfile = 'server_keypair.pem'

class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        self.server_usersfile = 'users.txt' # how do I add a new user to the users.txt. Should I be worried about that.
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        self.server_rootdir = './users/'
        self.server_ip = socket.gethostbyname('localhost')
        # self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_port = 5150
        # -------------------------------------------------------------
        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))
        self.accept_connections()


    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept() # connect the client to the server by the server accepting the socke
            threading.Thread(target=self.handle_client, args=(client_socket, addr, )).start()


    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        mtp = SiFT_MTP(client_socket)

        loginp = SiFT_LOGIN(mtp)
        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return
def newline(s):
    return s + b'\n'

# main
if __name__ == '__main__':
    generate_keypair(pubkeyfile, privkeyfile)
    server = Server()