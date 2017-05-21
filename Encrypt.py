from Crypto.Cipher import AES
from Crypto import Random
import pickle


class Encrypter :


    def __init__(self):
        self.session_key = 0
        self.data = 0


    def gen_key(self):
        return  Random.new().read(32)
    def gen_iv(self):
        return Random.new().read(16)

    def encryptAES(self, message, session_key=-1):
        # wrap data in bytes
        wrap_message = pickle.dumps(message)

        # make AES key and cipher
        if session_key == -1:
            self.session_key = self.gen_key()
        else:
            self.session_key = session_key
        iv = self.gen_iv()
        obj = AES.new(self.session_key, AES.MODE_CFB, iv)

        # encrypt data
        self.data = iv + obj.encrypt(wrap_message)