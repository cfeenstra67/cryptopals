#!/usr/local/bin/python3

import binascii
import base64
def m_gen(*args, fn):
	for arg in args: yield fn(arg)

def hex_to_base64(hex_string): 
	"""
	Convert a hexidecimal string to a base64 string

	>>> hex_to_base64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
	b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
	"""
	return binascii.b2a_base64(binascii.unhexlify(hex_string))[:-1]

def xor_strings(hex1, hex2):
	"""
	Decodes a hex string to base64 and xors it against a base64 string, returning a xor combination of the two

	>>> xor_strings(b'1c0111001f010100061a024b53535009181c', b'686974207468652062756c6c277320657965')
	b'746865206b696420646f6e277420706c6179'
	"""
	hbi1, hbi2 = m_gen(hex1, hex2, fn=binascii.unhexlify)
	b = bytes(a ^ b for a, b in zip(hbi1,cycle(hbi2)))
	return binascii.hexlify(b)

def find_xor_char(hex_str):
	"""
	Find the single character that the given hex-encoded string has been xored against

	>>> 
	"""

if __name__ == '__main__':
	import doctest, crypto
	doctest.testmod(crypto)