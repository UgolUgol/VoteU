import pickle
import zmq
import rsa
from Crypto.PublicKey import RSA
from Crypto import Random
from message_container import MessageContainer, RegistrationContainer
from blank import Blank
from Encrypt import Encrypter
from Decrypt import Decrypter
from digital_sign import DigitalSign, MD5
import sys


class Server:


    def __init__(self):
        self.port = "43000"
        self.connected_clients_count = 0
        self.status = 'no'

        self.key = 0
        self.clients_base = {}
        self.clients_status = {}
        self.clients_sckeys = {}
        self.clients_blanks = {}

        #voting blank with results
        self.server_blank = Blank()

        # encryptors & decryptors for data and signature
        self.encrypted_data = Encrypter()
        self.encrypted_signature = Encrypter()
        self.decrypted_data = Decrypter()
        self.decrypted_signature = Decrypter()

        self.dig_sign = DigitalSign()


    def create_blank(self):
        print("Please enter count of candidates")
        count = int(input())
        print("Please enter full name of candidates(first name, second name, patronymic :\n")
        for i in range(count):
            (fn, sn, pt) = input().split(" ")
            self.server_blank.add_candidate(fn, sn, pt)
        self.server_blank.print_all()


    def run_server(self, count):

        # create voting blank for server
        self.create_blank()

        print("Server was runned")
        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.bind("tcp://*:%s" % self.port)

        # new status
        self.status = 'registration'
        while self.connected_clients_count != count:
            self.client_registration(socket)

        # new status
        self.status = 'voting'
        while not self.all_vote():
            self.client_request(socket)

        # new status
        self.status = 'sending-sckeys'
        while not self.all_send_sckeys():
            self.client_request(socket)

        # new status
        self.status = 'collecting results'
        self.collect_results()

        # new status
        self.status = 'ready'
        while not self.all_exit():
            self.client_request(socket)


    def configure_server(self):

        # create server pub and private keys
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator)

        # save keys to file
        outpriv = open('server/server_private.pkl', 'wb')
        pickle.dump(self.key, outpriv)
        outpriv.close()



    def client_registration(self, socket):

        # get registration data
        (message, signature, session_key) = pickle.loads(socket.recv())
        wrap_message = 0

        # check is it vote request
        if signature != -1:

            # if you get cypher message for registration
            # then decrypt it
            if self.decrypt(message, signature, session_key):
                self.send_title(socket, 'You cannot vote in registration time, please wait :) ', 'vote-in-reg-time')

        # if it registration request
        elif message.request == 'reg':
            # increase number of clients
            self.connected_clients_count += 1
            message.client_id = self.connected_clients_count

            # add new client in base and save it on disk
            self.clients_base[message.client_id] = message.pubkey
            self.clients_status[message.client_id] = 'non-vote'
            self.save_base()

            # create registration answer for client
            message.pubkey = self.key.publickey()
            message.request = 'reg_ok'
            message.title = 'Your registration was successfully! ' \
                            'Welcome on Vote server, client' + str(message.client_id)

            # encrypt and send message
            socket.send(self.encrypt(message))

        # client send status-request
        elif message.request == 'status':
            socket.send(pickle.dumps(self.status))

    def client_request(self, socket):

        # get wrap message from client
        (data, signature, session_key) = pickle.loads(socket.recv())

        if self.decrypt(data, signature, session_key):

            # if command was vote then response blank
            if self.decrypted_data.data.request == 'vote':
                print("Request for vote from client", self.decrypted_data.data.client_id)

                # check client didn't vote yet
                if self.clients_status[self.decrypted_data.data.client_id] == 'non-vote':
                    self.send_blank(socket)
                else:
                    self.send_title(socket, "You have been already vote, you can't vote again :) ", 'vote-again')

            elif self.decrypted_data.data.request == 'send_blank':
                print("I've got vote blank from client", self.decrypted_data.data.client_id)

                # check client have 'have-blank' status
                if self.clients_status[self.decrypted_data.data.client_id] == 'have-blank':

                    # save client blank
                    self.save_clientblank()

                    # send answer to client that his voice has been taken
                    self.send_title(socket, 'You voice has been taken, thank you :) ', 'voice-ok')

            elif self.decrypted_data.data.request == 'send_sckey':

                print("I've get secret key from client", self.decrypted_data.data.client_id)
                # check if client had voted
                if self.clients_status[self.decrypted_data.data.client_id] == 'voted':

                    # save client secret key
                    self.save_sckey()

                    # send answer to client that his sckey saved
                    self.send_title(socket, 'Thank you for secret key, soon you can watch the results', 'save-sckey-ok')

            elif self.decrypted_data.data.request == 'get_results':

                if self.clients_status[self.decrypted_data.data.client_id] == 'sended_sckey':

                    # here send blank to client
                    self.send_results(socket)
                else:
                    self.send_title(socket, 'You cannot see results', 'not-avaliable')


            elif self.decrypted_data.data.request == 'exit':

                # if clear wants to exit from server, server must change client status
                self.clients_status[self.decrypted_data.data.client_id] = 'exited'
                print("Client", self.decrypted_data.data.client_id, " exited from server ")

                # send answer with gooooodbye :)
                self.send_title(socket, 'Goodbye :)', 'exit-cli')

            else:
                # else send warning
                print("Warning : Non-vote request")
                self.send_error(socket, data, signature)
        else:
            # send error
            self.send_error(socket, data, signature)


    def send_blank(self, socket):

        # create message with vote blank
        message = MessageContainer()
        message.client_id = self.decrypted_data.data.client_id
        message.request = 'send_blank'
        message.pubkey = self.key.publickey()
        message.title = 'This is your vote blank'
        message.blank = self.server_blank.copy()

        # mark client as got blank
        self.clients_status[message.client_id] = 'have-blank'

        # send blank for a client
        socket.send(self.encrypt(message))


    def send_results(self, socket):

        # create message with vote blank
        message = MessageContainer()
        message.client_id = self.decrypted_data.data.client_id
        message.request = 'send_result'
        message.pubkey = self.key.publickey()
        message.title = 'This is vote results'
        message.blank = self.server_blank

        # send blank for a client
        socket.send(self.encrypt(message))

    def send_title(self, socket, title, req):

        # create message with title
        message = MessageContainer()
        message.client_id = self.decrypted_data.data.client_id
        message.request = req
        message.title = title
        message.pubkey = self.key.publickey()

        # send to answer to client
        socket.send(self.encrypt(message))


    def send_error(self, socket, data, signature):

        # create error message
        message = MessageContainer()
        message.request = 'vote_error'

        # find the reason of error
        # if sign == -1 it is registration or status request
        if signature == -1:

            # maybe it status request ?
            if data.request == 'status':
                socket.send(pickle.dumps(self.status))


            # else it is maybe registration in vote time => send error
            elif data.request == 'reg':
                message.title = 'You cannot register in system in vote time'
                socket.send(pickle.dumps((message, signature, -1)))

        # if you not in system send error
        elif self.decrypted_data.data.client_id not in self.clients_base:
            message.title = 'You are not register in system'
            socket.send(self.encrypt(message))

        # unknown error
        else :
            message.title = 'Unknown command'
            socket.send(self.encrypt(message))



    def encrypt(self, message):

        # encrypt message with simmetric AES
        self.encrypted_data.encryptAES(message)

        # make digital signature and encrypt it with AES
        self.dig_sign.make_sign(message, self.key)
        self.encrypted_signature.encryptAES(self.dig_sign.signature,
                                            self.encrypted_data.session_key)

        # find client pubkey in base
        pubkey = self.clients_base[message.client_id]

        # encrypt session key
        ensession_key = pubkey.encrypt(pickle.dumps(self.encrypted_data.session_key), 32)

        # wrap data
        wrap_message = pickle.dumps((self.encrypted_data.data,
                                     self.encrypted_signature.data, ensession_key))
        return wrap_message


    def decrypt(self, data, signature, session_key):

        # check if this is non-cypher request
        if signature == -1:
            return False

        # decrypt session key with your private key
        session_key = pickle.loads(self.key.decrypt(session_key))

        # decrypt message from server
        self.decrypted_data.decryptAES(data, session_key)

        # decrypt signature with your private key
        self.decrypted_signature.decryptAES(signature, session_key)

        # check legacy
        if self.valid_data(signature):
            return True
        else:
            return False


    def valid_data(self, signature) :

        # found client pubkey in base if it was reg
        if self.decrypted_data.data.client_id in self.clients_base:
            client_pubkey = self.getfrom_base(self.decrypted_data.data.client_id)

            # count md5 under data and return result
            cs = MD5.new(self.decrypted_data.wrap_data).digest()
            signature = self.decrypted_signature.data
            return (client_pubkey.verify(cs, signature))
        else:
            return False


    def getfrom_base(self, idx):
        return self.clients_base[idx]


    def all_vote(self):

        # while not all clients voted or maybe someone exited
        for stat in self.clients_status:
            if self.clients_status[stat] != 'voted' and self.clients_status[stat] != 'exited':
                return False
        return True

    def all_send_sckeys(self):

        # while not all clients send mask
        for stat in self.clients_status:
            if self.clients_status[stat] != 'sended_sckey' and self.clients_status[stat] != 'exited':
                return False
        return True

    def all_exit(self):

        # while not all clients exit
        for stat in self.clients_status:
            if self.clients_status[stat] != 'exited':
                return False
        return True

    def save_base(self):
        outbase = open('server/base.pkl', 'wb')
        pickle.dump(self.clients_base, outbase)
        outbase.close()

    def save_clientblank(self):

        # add blank to base of blanks
        self.clients_blanks[self.decrypted_data.data.client_id] = self.decrypted_data.data.blank

        # add client new status
        self.clients_status[self.decrypted_data.data.client_id] = 'voted'

    def save_sckey(self):

        # add sckey to base of sckeys
        self.clients_sckeys[self.decrypted_data.data.client_id] = self.decrypted_data.data.pubkey

        # add client new status
        self.clients_status[self.decrypted_data.data.client_id] = 'sended_sckey'


    def collect_results(self):

        # decryptor for blanks
        blank_decryptor = Decrypter()
        for id in self.clients_blanks:

            #   if client didn't exit
            if self.clients_status[id] == 'sended_sckey':

                # decrypt blank
                blank_decryptor.decryptAES(self.clients_blanks[id], self.clients_sckeys[id])
                self.clients_blanks[id] = blank_decryptor.data

                # add blank to results
                self.server_blank = self.server_blank + self.clients_blanks[id]

        print("Results ready for publishing")
