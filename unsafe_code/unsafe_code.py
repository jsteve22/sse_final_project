from Crypto.Cipher import DES
key = b'-8B key-'
cipher = DES.new(key, DES.MODE_OFB)
plaintext = b'sona si latine loqueris'
msg = cipher.iv + cipher.encrypt(plaintext)
