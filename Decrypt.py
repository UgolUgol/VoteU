from Crypto.Cipher import AES
from Crypto import Random
import pickle


class Decrypter :

    def __init__(self):
        self.data = 0
        self.wrap_data = 0

    def decryptAES(self, message, session_key):
        iv = message[:16]
        obj = AES.new(session_key, AES.MODE_CFB, iv)
        self.wrap_data = obj.decrypt(message)
        self.wrap_data = self.wrap_data[16:]

        self.data = pickle.loads(self.wrap_data)