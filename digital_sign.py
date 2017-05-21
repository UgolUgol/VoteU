import hashlib
import pickle
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5


class DigitalSign :

    def __init__(self):
        self.signature = 0

    def make_sign(self, message, privkey):
        # wrap our message
        wrap_message = pickle.dumps(message)

        # count control sum
        control_sum = MD5.new(wrap_message).digest()

        # cypher sum with server privkey
        self.signature = privkey.sign(control_sum, '')
