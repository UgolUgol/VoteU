import zmq
import random
import pickle
from message_container import MessageContainer, RegistrationContainer
from blank import Blank
from digital_sign import DigitalSign
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random
from Encrypt import Encrypter
from Decrypt import Decrypter


class Client:

    def __init__(self):
        self.port = "43000"

        # encryptors & decryptors for data and signature
        self.decrypted_data = Decrypter()
        self.decrypted_signature = Decrypter()
        self.encrypted_data = Encrypter()
        self.encrypted_signature = Encrypter()

        # digital signature
        self.dig_sign = DigitalSign()

        self.client_id = 0
        self.path_priv = 'client/client_priv'

        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator)
        self.server_pubkey = 0

        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect("tcp://localhost:%s" % self.port)

        # secret key
        self.sckey = Encrypter()


    def registration(self):

        # check maybe user already register in system
        if self.client_id != 0:
            print("You have been already in system")
            return 'already_reg_in'

        # create command to server
        message = RegistrationContainer()
        message.request = 'reg'
        message.pubkey = self.key.publickey()
        wrap_message = pickle.dumps((message, -1, -1))

        # sending request for a registration
        self.socket.send(wrap_message)

        # getting answer from server
        (is_correct, data, signature, session_key) = self.get_answer()

        if is_correct:
            self.client_id = self.decrypted_data.data.client_id
            self.server_pubkey = self.decrypted_data.data.pubkey
            self.save_keys()
            print(self.decrypted_data.data.title)

            # return response from server
            return self.decrypted_data.data.request
        else:
            return self.print_error(data, signature)


    def valid_data(self, signature) :

        # count md5 under data and return result
        cs = MD5.new(self.decrypted_data.wrap_data).digest()
        signature = self.decrypted_signature.data
        return (self.decrypted_data.data.pubkey.verify(cs, signature))



    def save_keys(self):
        # create directory path
        self.path_priv += str(self.client_id) + ".pkl"

        # open file
        outpriv = open(self.path_priv, 'wb')

        # making pickle dump
        pickle.dump(self.key, outpriv)

        # close stream
        outpriv.close()

    def vote(self):

        # check you reg in system
        if self.client_id == 0:
            print("You didn't register in system and cannot vote")
            return 'reg_no'

        # create command to server
        message = MessageContainer()
        message.request = 'vote'
        message.client_id = self.client_id

        # send cypher message
        self.socket.send(self.encrypt(message))

        # wait for answer with blank
        (is_correct, data, signature, session_key) = self.get_answer()

        if is_correct:

            # title from server
            print(self.decrypted_data.data.title)

            # check type of response from server
            if self.decrypted_data.data.request == 'send_blank':
                self.decrypted_data.data.blank.print_all()

                # send filled blank to server and wait answer
                self.send_blank( self.fill_blank() )

            # return response from server
            return self.decrypted_data.data.request
        else:
            return self.print_error(data, signature)


    def send_sckey(self):

        if self.client_id == 0:
            print("You didn't register !")
            return 'reg_no'

        # get server status
        # if now sending sckeys
        elif self.get_server_status() == 'sending-sckeys':
            message = MessageContainer()
            message.request = 'send_sckey'
            message.client_id = self.client_id

            # now message.pubkey plays role of secret key
            message.pubkey = self.sckey.session_key

            # send secret key to server
            self.socket.send(self.encrypt(message))

            # get answer from server
            (is_correct, data, signature, session_key) = self.get_answer()

            if is_correct:
                print(self.decrypted_data.data.title)
            else:
                print("Unknown error")
            return self.decrypted_data.data.request
        else :
            # it's not time for sending keys now
            print("You can send secret key only after vote time")
            return 'no-time'

    def get_results(self):

        # check we reg-in
        if self.client_id == 0:
            print("You didn't registered yet")
            return 'reg-no'

        # if server ready to give results
        elif self.get_server_status() == 'ready':
            message = MessageContainer()
            message.request = 'get_results'
            message.client_id = self.client_id

            # send request for results for server
            self.socket.send(self.encrypt(message))

            (is_correct, data, signature, session_key) = self.get_answer()

            if is_correct:
                print(self.decrypted_data.data.title)
                print(self.decrypted_data.data.blank.print_full_blank())
                return self.decrypted_data.data.request
            else :
                print("Unknown error")
                return 'unknown-error'

        # if not ready
        else:
            print("You cannot get results at this time, please wait until ending")
            return 'not-avaliable'

    def exit(self):

        # if client didn't register in system he can exit easy,
        # but if he registered he must send request for changing status
        if self.client_id != 0:
            message = MessageContainer()
            message.request = 'exit'
            message.client_id = self.client_id
            self.socket.send(self.encrypt(message))

            # get answer from server
            (is_correct, data, signature, session_key) = self.get_answer()

            if is_correct:
                print(self.decrypted_data.data.title)
            else:
                print("Unknown error")

            return self.decrypted_data.data.request

        else :
            print(" Bye :) ")
            return 'exit-cli'


    def get_server_status(self):

        message = MessageContainer()
        message.request = 'status'
        wrap_message = pickle.dumps((message, -1, -1))

        # send status request
        self.socket.send(wrap_message)

        # get answer from server
        status = pickle.loads(self.socket.recv())
        return status



    def get_answer(self):


        # get response from server
        (data, signature, session_key) = pickle.loads(self.socket.recv())

        if self.decrypt(data, signature, session_key):
            return (True, data, signature, session_key)
        else :
            return (False, data, signature, session_key)

    def fill_blank(self):

        # create answer blank
        client_blank = self.decrypted_data.data.blank

        # vote process
        print("Please, enter for every candidate your score (from 1 to 5)")
        for i in range(len(self.decrypted_data.data.blank.candidates)):
            voice = 0

            # check right voice
            while voice <=0 or voice > 5:
                print(i + 1, " : ")
                voice = int(input())

            # add voices to candidate
            client_blank.vote_for(i, voice=voice)

        return client_blank



    def send_blank(self, blank):

        # encrypt blank with aes
        self.sckey.encryptAES(blank)

        # create message with blank
        message = MessageContainer()
        message.request = 'send_blank'
        message.client_id = self.client_id
        message.blank = self.sckey.data

        # send encrypt message with blank to server
        self.socket.send(self.encrypt(message))

        (is_correct, data, signature, session_key) = self.get_answer()

        if is_correct:
            print(self.decrypted_data.data.title)



    def encrypt(self, message):

        # encrypt message with simmetric AES
        self.encrypted_data.encryptAES(message)

        # make digital signature and encrypt it with AES
        self.dig_sign.make_sign(message, self.key)
        self.encrypted_signature.encryptAES(self.dig_sign.signature,
                                            self.encrypted_data.session_key)

        # encrypt session key
        ensession_key = self.server_pubkey.encrypt(pickle.dumps(self.encrypted_data.session_key), 32)

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


    def print_error(self, data, signature):

        # if signature -1 then non-register error
        if signature == -1:
            print(data.title)
            return data.request
        # else another error
        else :
            print(self.decrypted_data.data.title)
            return self.decrypted_data.data.request

    def print_help(self):
        print("reg - registration on server")
        print("vote - request for vote")
        print("send-sckey - sending your secret key to server")
        print("results - watch results of election")