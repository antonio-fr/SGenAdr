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


def compute_adr(priv_num):
	pubkey = Public_key( generator_256, mulG(priv_num) )
	pubkeystr = pubkey.print_hex()
	return pubkeystr,pub_hex_base58(pubkey.point.x(),pubkey.point.y())

if __name__ == '__main__':
	import re
	import sys
	import os.path
	try:
		assert len(sys.argv) == 2
		arg1 = sys.argv[1]
		numadr = int(arg1)
	except:
		raise ValueError("Error in arguments\nUse :     SGenAdr.py <number of adresses to generate>\n]")
	print "\n--- Generate %i new Bitcoin accounts ---\n" % numadr
	load_gtable('lib/G_Table')
	nanos_dongle = getDongle()
	rawversions = nanos_dongle.exchange(bytes("E0C4000000".decode('hex')))
	version = rawversions[2:5]
	print "Nano S dongle detected\n version %s\n" % ".".join(map(str, version))
	# Improvement : perform signature attestation genuine check
	getrandom = "E0C000"+"0200" # 0x0200 bytes = 512 bytes = 16 x 256b
	f = open('address_list.csv', 'wb')
	f.write("index,pubkey,address,prvkeyWIP\r\n")
	for i in xrange(numadr):
		candint = 0
		while candint<1 or candint>=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L:
			random_from_nanos = nanos_dongle.exchange(bytes(getrandom.decode('hex')))
			cand = hashlib.sha256(random_from_nanos).hexdigest()
			candint = int(cand,16)
		privkeynum = candint
		pvkeywip = priv_hex_base58(privkeynum)
		pubkey , address = compute_adr(privkeynum)
		istr = str(i+1)
		print "Account #"+istr
		print "PrivKey :  %s" % pvkeywip
		print "Address :  %s\n" % address
		linew = ",".join([istr,pubkey, address, pvkeywip])
		f.write(linew+"\r\n")
	f.close()
