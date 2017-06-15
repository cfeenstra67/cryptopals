#!/usr/local/bin/python3

import binascii
import pickle
import numpy as np
from pprint import pprint
from itertools import cycle, zip_longest, combinations
from math import factorial as fact
from heapq import heapify, heappop
from time import time

def m_gen(*args, fn):
	for arg in args: yield fn(arg)
def grouper(iterable, n, fillvalue=None):
	args = [iter(iterable)] * n
	return zip_longest(*args, fillvalue=fillvalue)
def arr_for_string(s, lower=False):
	arr = np.zeros(264)
	for char in bytes(s.lower() if lower else s, encoding='utf-8'):
		arr[char] += 1
	return arr / np.sum(arr)

def hex_to_base64(hex_string): 
	"""
	Cryptopals 1.1
	Convert a hexidecimal string to a base64 string

	>>> hex_to_base64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
	b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
	"""
	return binascii.b2a_base64(binascii.unhexlify(hex_string))[:-1]

def xor_binary(bi1, bi2):
	"""
	Xors two byte strings.  The second one may be shorter than the first, including a single integer.
	"""
	if isinstance(bi2, int): bi2 = (bi2,)
	return bytes(a ^ b for a, b in zip(bi1, cycle(bi2)))

def xor_hexes(hex1, hex2):
	"""
	Cryptopals 1.2
	Xors two hex strings of equal length

	>>> xor_hexes(b'1c0111001f010100061a024b53535009181c', b'686974207468652062756c6c277320657965')
	b'746865206b696420646f6e277420706c6179'
	"""
	hbi1, hbi2 = m_gen(hex1, hex2, fn=binascii.unhexlify)
	return binascii.hexlify(xor_binary(hbi1, hbi2))

def retrieve_model(filename='model.pkl'):
	"""
	Retrieve probability model pickled into a file.
	""" 
	with open(filename, 'rb') as modfile: return pickle.load(modfile)

def predict_string(some_str, model=None):
	"""
	Returns the predicted probability that the given string is English
	"""
	if model is None:
		try: model = retrieve_model()
		except FileNotFoundError: raise FileNotFoundError('Model File Not Found.')
	str_arr = arr_for_string(str(some_str))
	(n, y), = model.predict_proba(str_arr.reshape(1, -1))
	return y

def find_xor_char(hex_str, model=None):
	"""
	Cryptopals 1.3
	Find the single character that the given string has been xored against.
	Returns (key, probability) tuple where probability is the estimated probability of
	that string being english.

	>>> ex = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	>>> unhexed = binascii.unhexlify(ex)
	>>> key = find_xor_char(unhexed)[0]
	>>> key
	88
	>>> xor_binary(unhexed, key)
	b"Cooking MC's like a pound of bacon"
	"""
	if model is None: model = retrieve_model()

	return max([(i, predict_string(xor_binary(hex_str, i), model)) for i in range(256)], 
		key=lambda p: p[1])

def find_char_xorred(*args, model=None):
	"""
	Cryptopals 1.4
	Given a list of 60-character hex-encoded strings which have been encrypted using
	a single-character XOR, find the one most likely to be an english string.  Returns
	(line_number, key) tuple, where line_number is the 0-based index of the 'winning'
	argument and key is the byte corresponding to the character used to decrypt the
	message.
	
	Uncomment below to test this function when running from the command line. It is 
	expensive so leaving it out is more practical while using testing other functions.

	#>>> with open('4.txt', 'rb') as f: lines = [line[:60] for line in f]
	#>>> line_number, key = find_char_xorred(*lines)
	#>>> line = lines[line_number]
	#>>> print(xor_binary(binascii.unhexlify(line), key)[:-1])
	#b'Now that the party is jumping'
	"""
	if model is None: model = retrieve_model()

	def prob(line, key): 
		return predict_string(xor_binary(binascii.unhexlify(line), key))

	line, key, prob = 0, 0, 0
	for ind, arg in enumerate(args):
		if len(arg) == 60:
			k = find_xor_char(binascii.unhexlify(arg), model)[0]
			p = prob(arg, key)
			if p > prob: line, key, prob = ind, k, p
	return line, key

def encrypt_rkXOR(string, key):
	"""
	Cryptopals 1.5
	Encrypt the given string using repeating-key XOR.
	Both strings should be of the bytes type.
	Returns encrypted string, hex-encoded.

	>>> encrypt_rkXOR(b"Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal", b'ICE')
	b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
	"""
	encrypted = xor_binary(string, key)
	return binascii.hexlify(encrypted)

def decrypt_rkXOR(hex_str, key):
	"""
	Inverse of encrypt_rkXOR.  Takes a hex-encoded string and decrypts it based on the key

	>>> s = b'Hello, World!'
	>>> k = b'LOL'
	>>> decrypt_rkXOR(encrypt_rkXOR(s, k), k) == s
	True
	"""
	bin_str = binascii.unhexlify(hex_str)
	return xor_binary(bin_str, key)

def str_diff(str1, str2):
	"""
	Calculate Hamming Distance between two strings.

	>>> str_diff(b'this is a test', b'wokka wokka!!!')
	37
	"""
	return sum(bin(a ^ b).count('1') for a, b in zip(str1, str2))

#Abstractions created for crack_rkXOR

def av_distance(blocks):
	def num_combos(n, k): return fact(n)//(fact(k) * fact(n-k))
	combos = combinations(blocks, 2)
	return sum(str_diff(a, b) for a, b in combos) / num_combos(len(blocks), 2)

class keyedlist(list):
	def __init__(self, *ob, key=lambda x: x[1]):
		super().__init__(ob)
		self.key = key
	def __lt__(self, other): return self.key(self) < other.key(other)

def distances(string, num_blocks, keysizes):
	l = len(string)
	for keysize in keysizes:
		if num_blocks * keysize <= l:
			g = grouper(string, keysize)
			blocks = tuple(m_gen(*([g]*num_blocks), fn=next))
			yield keyedlist(keysize, av_distance(blocks) / keysize)

def top_n(ob, n, transform_fn=lambda x: x):
	for i in range(n):
		heapify(ob)
		yield transform_fn(heappop(ob))


def crack_rkXOR(string, keysize_range=(2,40), chunks=4, consider=3, model=None):
	"""
	Cryptopals 1.6
	Crack an rkXOR-encrypted string.  Returns (key, probability) tuple where probability
	is the estimated probability the string found by decrypting the message with the key
	is English (average of probabilities that each character in the key is correct)

	Arguments:

	chunks - number of chunks of keysize_range sized data to consider when
	analyzing keysizes

	consider - number of top keysize values to consider

	>>> with open('6.txt', 'rb') as f: full = binascii.a2b_base64(f.read())
	>>> crack_rkXOR(full)[0]
	b'Terminator X: Bring the noise'
	"""

	dists = [*distances(string, chunks, range(*keysize_range))]
	top_vals = [*top_n(dists, consider, transform_fn=lambda x: x[0])]
	if model is None: model = retrieve_model()

	def best_key(keysize):
		vals = []
		probsum = 0
		for seg in zip_longest(*grouper(string, keysize, fillvalue=0)):
			key, prob = find_xor_char(seg, model=model)
			probsum += prob
			vals.append(key)
		return vals, probsum / keysize

	key, prob = max((best_key(ksize) for ksize in top_vals), key=lambda x: x[1])
	return bytes(key), prob

from Crypto.Cipher import AES

def decrypt_AES(string, key):
	"""
	Decrypts a given string, assuming it has been encrypted using key.

	>>> with open('7.txt', 'rb') as f: full = binascii.a2b_base64(f.read())
	>>> decrypt_AES(full, b'YELLOW SUBMARINE')[:25]
	b"I'm back and I'm ringin' "
	"""
	dl = 16
	ciph = AES.new(key, AES.MODE_ECB, b'')
	decrypted = b''
	for chunk in grouper(string, dl, fillvalue=0):
		decrypted += ciph.decrypt(bytes(chunk))
	return decrypted

def encrypt_AES(string, key):
	"""
	Inverse of decrypt_AES

	>>> k = b'YELLOW SUBMARINE'
	>>> string = b"I'm back and I'm ringin' " * 16
	>>> decrypt_AES(encrypt_AES(string, k), k) == string
	True
	"""
	dl = 16
	ciph = AES.new(key, AES.MODE_ECB, b'')
	encrypted = b''
	for chunk in grouper(string, dl, fillvalue=0):
		encrypted += ciph.encrypt(bytes(chunk))
	return encrypted

def prob_AES(string, model=None):
	if model is None: model = retrieve_model()
	for seg in zip_longest(*grouper(string, 16), fillvalue=0): pass

def keysum(iterable, key=lambda x: x):
	return sum(key(val) for val in iterable)

def detect_AES(*strings, chunks=None):
	"""
	Cryptopals 1.8
	Given equal-length strings, determine which one has been encrypted with ECB.

	>>> with open('8.txt', 'rb') as f: full = [binascii.unhexlify(line[:-1]) for line in f]
	>>> ind = detect_AES(*full)[0]
	>>> ind
	132
	"""
	dl = 16
	if chunks is None: chunks = len(strings[0]) // dl
	vals = []
	def sames(string, num):
		g = grouper(string, dl)
		blocks = m_gen(*[g]*num, fn=next)
		same = 0
		for a, b in combinations(blocks, 2):
			if a == b: same += 1
		return same
	for ind, string in enumerate(strings):
		s = sames(string, chunks)
		ks, d = [*distances(string, chunks, [dl])][0]
		vals.append((ind, s, d))
	ss, sd = m_gen(1, 2, fn=lambda n: keysum(vals, lambda x: x[n]))
	vals = [(ind, (s / ss + d / sd) / 2) for ind, s, d in vals]
	return max(vals, key=lambda x: x[1])


if __name__ == '__main__':
	import doctest, cryptopals1
	doctest.testmod(cryptopals1)
















