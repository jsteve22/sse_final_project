# Source: https://gist.github.com/hadrian3689/a6129b5d1ef8a58e837826cfc0f8ccfe#file-random_session_key_calc-py

import hashlib
import hmac
import argparse

#stolen from impacket. Thank you all for your wonderful contributions to the community
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
   cipher = ARC4.new(keyExchangeKey)
   cipher_encrypt = cipher.encrypt

   sessionKey = cipher_encrypt(exportedSessionKey)
   return sessionKey
###

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u","--user",required=True,help="User name")
parser.add_argument("-d","--domain",required=True, help="Domain name")
parser.add_argument("-p","--password",required=False,help="Password of User")
parser.add_argument("-H","--hash",required=False,help="Password Hash of User")
parser.add_argument("-n","--ntproofstr",required=True,help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k","--key",required=True,help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

#Upper Case User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

#Create 'NTLM' Hash of password
if args.password:
    passw = args.password.encode('utf-16le')
    hash1 = hashlib.new('md4', passw)
    password = hash1.digest()
    if not args.hash:
        LOG.critical("Doesn't work without a password (-p) or at least a hash (-h)!! Exiting")
        exit
else:
    password = args.hash.decode('hex')

#Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user+domain)
respNTKey = h.digest()

#Use NTProofSTR and ResponseNTKey to calculate Key Excahnge Key
NTproofStr = args.ntproofstr.decode('hex')
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

#Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey,args.key.decode('hex'))

if args.verbose:
    print "USER WORK: " + user + "" + domain
    print "PASS HASH: " + password.encode('hex')
    print "RESP NT:   " + respNTKey.encode('hex')
    print "NT PROOF:  " + NTproofStr.encode('hex')
    print "KeyExKey:  " + KeyExchKey.encode('hex')
    print "Random SK: " + RsessKey.encode('hex')
