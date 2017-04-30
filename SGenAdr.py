#!/usr/bin/env python
# coding=utf8

# SGenAdr : Secure Bitcoin Address Generator
# Copyright (C) 2017  Antoine FERRON
#
# Python address generator from secure random source
# 
# Random source for key generation :
# AIS-31 Class PTG.2 compliant true random number generator (TRNG)
# from Ledger Nano S
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
#

from lib.ECDSA_BTC import *
import hashlib
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from ledgerblue.ecWrapper import PrivateKey, PublicKey
from ledgerblue.hexLoader import HexLoader
import argparse
import struct
import os
import binascii
import random
import re
import sys

def auto_int(x):
    return int(x, 0)

def getDeployedSecretV2(dongle, masterPrivate, targetid, issuerKey):
        testMaster = PrivateKey(bytes(masterPrivate))
        testMasterPublic = bytearray(testMaster.pubkey.serialize(compressed=False))
        targetid = bytearray(struct.pack('>I', targetid))

        # identify
        apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
        dongle.exchange(apdu)

        # walk the chain 
        nonce = os.urandom(8)
        apdu = bytearray([0xe0, 0x50, 0x00, 0x00]) + bytearray([len(nonce)]) + nonce
        auth_info = dongle.exchange(apdu)
        batch_signer_serial = auth_info[0:4]
        deviceNonce = auth_info[4:12]

        # if not found, get another pair
        #if cardKey != testMasterPublic:
        #       raise Exception("Invalid batch public key")

        dataToSign = bytes(bytearray([0x01]) + testMasterPublic)        
        signature = testMaster.ecdsa_sign(bytes(dataToSign))
        signature = testMaster.ecdsa_serialize(signature)
        certificate = bytearray([len(testMasterPublic)]) + testMasterPublic + bytearray([len(signature)]) + signature
        apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
        dongle.exchange(apdu)
        
        # provide the ephemeral certificate
        ephemeralPrivate = PrivateKey()
        ephemeralPublic = bytearray(ephemeralPrivate.pubkey.serialize(compressed=False))
        dataToSign = bytes(bytearray([0x11]) + nonce + deviceNonce + ephemeralPublic)
        signature = testMaster.ecdsa_sign(bytes(dataToSign))
        signature = testMaster.ecdsa_serialize(signature)
        certificate = bytearray([len(ephemeralPublic)]) + ephemeralPublic + bytearray([len(signature)]) + signature
        apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
        dongle.exchange(apdu)

        # walk the device certificates to retrieve the public key to use for authentication
        index = 0
        last_pub_key = PublicKey(binascii.unhexlify(issuerKey), raw=True)
        while True:
                if index == 0:                  
                        certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
                elif index == 1:
                        certificate = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))
                else:
                                break
                if len(certificate) == 0:
                        break
                offset = 1
                certificateHeader = certificate[offset : offset + certificate[offset-1]]
                offset += certificate[offset-1] + 1
                certificatePublicKey = certificate[offset : offset + certificate[offset-1]]
                offset += certificate[offset-1] + 1
                certificateSignatureArray = certificate[offset : offset + certificate[offset-1]]
                certificateSignature = last_pub_key.ecdsa_deserialize(bytes(certificateSignatureArray))
                # first cert contains a header field which holds the certificate's public key role
                if index == 0:
                        certificateSignedData = bytearray([0x02]) + certificateHeader + certificatePublicKey
                        # Could check if the device certificate is signed by the issuer public key
                # ephemeral key certificate
                else:
                        certificateSignedData = bytearray([0x12]) + deviceNonce + nonce + certificatePublicKey          
                if not last_pub_key.ecdsa_verify(bytes(certificateSignedData), certificateSignature):
                        return None
                last_pub_key = PublicKey(bytes(certificatePublicKey), raw=True)
                index = index + 1

        # Commit device ECDH channel
        dongle.exchange(bytearray.fromhex('E053000000'))
        secret = last_pub_key.ecdh(binascii.unhexlify(ephemeralPrivate.serialize()))
        return secret[0:16]


def compute_adr(priv_num):
	pubkey = Public_key( generator_256, mulG(priv_num) )
	pubkeystr = pubkey.print_hex()
	return pubkeystr,pub_hex_base58(pubkey.point.x(),pubkey.point.y())

if __name__ == '__main__':
	try:
		assert len(sys.argv) == 2
		arg1 = sys.argv[1]
		numadr = int(arg1)
		assert numadr >= 2
	except:
		raise ValueError("Error in arguments\nUse :     SGenAdr.py <Number of Adresses to Generate (>1)>\n]")
	load_gtable('lib/G_Table')
	use_nano = True
	try:
		nanos_dongle = getDongle()
		# ID and Issuer_PubKey from :
		# http://support.ledgerwallet.com/knowledge_base/topics/how-to-verify-the-security-integrity-of-my-nano-s (no HTTPS yet)
		targetId = 0x31100002
		issuerKey = "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609"
		privateKey = PrivateKey()
		publicKey = str(privateKey.pubkey.serialize(compressed=False)).encode("hex").upper()
		rootPrivateKey = privateKey.serialize()
		genuine = False
		print "\nConfirm in the NanoS this Public key : "+publicKey[4:8]+".."+publicKey[-6:-2]
		secret = getDeployedSecretV2(nanos_dongle, bytearray.fromhex(rootPrivateKey), targetId, issuerKey)
		if secret != None:
				loader = HexLoader(nanos_dongle, 0xe0, True, secret)
				data = b'\xFF'
				data = loader.encryptAES(data)
				try:
						loader.exchange(loader.cla, 0x00, 0x00, 0x00, data)                             
				except CommException as e:
						genuine = (e.sw == 0x6D00)
		assert genuine
		print "\nGenuine Nano S dongle detected\n"
		raw_input("Launch Bitcoin App in the NanoS, then press ENTER")
		nanos_dongle.close()
		nanos_dongle = getDongle() # Change because different mode and ID
		rawversions = nanos_dongle.exchange(bytes("E0C4000000".decode('hex')))
		version = rawversions[2:5]
		print "NanoS Bitcoin App version %s\n" % ".".join(map(str, version))
	except:
		print "\n--- WARNING : No genuine NanoS connected ---\n"
		print "Make sure : - You installed with 'pip install ledgerblue'\n            - Connect NanoS and enter PIN (on main menu, no in app)\n\n"
		cont = raw_input("Will you continue using RNG from this machine OS? (Y/[N])")
		if cont!="Y":
			quit()
		use_nano = False
	getrandom = "E0C000"+"00C0" # 0x00C0 bytes = 192 bytes = 6 x 256b
	print "\n--- Generating %i new Bitcoin accounts ---\n" % numadr
	if  not use_nano:
		print " WARNING : Generation from this machine's random source (not from NanoS)\n"
	f = open('address_list.csv', 'wb')
	fpv = open('PvKeysList.json', 'wb')
	f.write("index,pubkey,address\r\n")
	fpv.write("[")
	rndg = random.SystemRandom()
	for i in xrange(numadr):
		candint = 0
		while candint<1 or candint>=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L:
			if use_nano:
				assert genuine
				random1_from_nanos = bytes(nanos_dongle.exchange(bytes(getrandom.decode('hex')))) # Get 12 chucks of 256 random bits from PTG2 TRNG
				random2_from_nanos = bytes(nanos_dongle.exchange(bytes(getrandom.decode('hex')))) #     6x2
				random_from_nanos = random1_from_nanos + random2_from_nanos
			else:
				random_from_nanos = bytes(os.urandom(384))
			assert random_from_nanos.__len__() == 384
			rnd_nano_list = []
			for x in range(12):
				rnd_nano_list.append(random_from_nanos[32*x:32*(x+1)])
			sel_random = rndg.sample(rnd_nano_list, 8)             # Get 8 random chuncks out of the 12
			cand = hashlib.sha256("".join(sel_random)).hexdigest() # get 256 bits from 256 random-source bytes
			candint = int(cand,16)
		privkeynum = candint
		pvkeywip = priv_hex_base58(privkeynum)
		pubkey , address = compute_adr(privkeynum)
		istr = str(i+1)
		print "Account #"+istr
		print "Address :  %s\n" % address
		linew = ",".join([istr,pubkey, address])
		f.write(linew+"\r\n")
		fpv.write("\""+pvkeywip+"\", ")
	f.close()
	fpv.write("];")
	fpv.close()
	print "--- Generation of  %i accounts successfully done :) ---" % numadr
	if not use_nano:
		print " WARNING : Generation from this machine's random source (not from NanoS)\n"
	print "Addresses in 'address_list.csv' file"
	print "Private Keys in 'PvKeysList.json' file\n"
