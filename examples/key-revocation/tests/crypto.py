from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
NONCE_LEN = 13
KEY = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

MIC_LEN = 8

def encrypt(plaintext, nonce=NONCE, key=KEY):
    hdr = ""
    padded_nonce = nonce + (NONCE_LEN - len(nonce)) * "\xff"
    cipher = AES.new(key, mode=AES.MODE_CCM, nonce=padded_nonce, mac_len=MIC_LEN)
    # cipher.update(hdr)
    msg = cipher.encrypt(plaintext) + cipher.digest()
    return msg

def decrypt(msg, nonce=NONCE, key=KEY):
    ciphertext, mac = msg[:-MIC_LEN], msg[-MIC_LEN:]
    hdr = ""
    padded_nonce = nonce + (NONCE_LEN - len(nonce)) * "\xff"
    # print padded_nonce.encode("hex")
    cipher = AES.new(key, mode=AES.MODE_CCM, nonce=padded_nonce, mac_len=MIC_LEN)
    # cipher.update(hdr)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mac)
        return plaintext
    except ValueError:
        c = AES.new(key, mode=AES.MODE_CCM, nonce=padded_nonce, mac_len=MIC_LEN)
        print "Encrypted Message:", msg.encode("hex")
        print "Encrypted plaintext:", (c.encrypt(plaintext) + c.digest()).encode("hex")
        print "Plaintext:", plaintext
        return "<MAC Error>: " + plaintext

# m = encrypt("test", "")
# print m

# print decrypt((c, mic), "")
