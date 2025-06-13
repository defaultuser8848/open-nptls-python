from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
def generate_key_pair():
    private_key = ECC.generate(curve='secp256r1')
    public_key = private_key.public_key()
    return private_key, public_key

class ECDH:
    def __init__(self, private_key, peer_public_key):
        shared_point = private_key.d * peer_public_key.pointQ
        self.shared_secret = HKDF(shared_point.x.to_bytes(32,'big'), 32, b'', SHA256)

    def encrypt(self, plaintext):
        """返回 (nonce, ciphertext, tag)"""
        cipher = AES.new(self.shared_secret, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, ciphertext, tag 

    def decrypt(self, nonce, ciphertext, tag):
        """验证并解密，失败抛出ValueError"""
        cipher = AES.new(self.shared_secret, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)