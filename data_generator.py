#!/usr/bin/local/python3

from txt_learn import add_text_sample

#std_length informs the size of the strings to be inserted into the database
std_length=250

#Generating Random Samples
import string
import random
potential_chars=string.ascii_uppercase+string.ascii_lowercase+'.,;\'\"()'

def add_random_text_samples(num=1,length=std_length):
	"""
	Creates random text samples w/ given length and enter it into the database managed in txt_learn.py
	"""
	for _ in range(num):
		new_sample=''.join(random.choice(potential_chars) for _ in range(length))
		add_text_sample('_',0,new_sample)