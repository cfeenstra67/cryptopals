#!/usr/bin/local/python3

"""
NOTE: When including text files as command line arguments, their names must not begin with a hyphen or they will be ignored.
"""

from data_manager import add_text_sample, DATA_FOLDER, get_all_samples, DATAFRAME_DEST, abs_path, clear_all_samples
from txt_learn import arr_for_string
import pandas as pd
import numpy as np
from collections import Counter
import pickle

#std_length informs the size of the strings to be inserted into the database
std_length=250

#Generating Random Samples
import string
import random
potential_chars=string.ascii_uppercase+string.ascii_lowercase+'.,;()!?:'

def add_random_text_samples(num=1,length=std_length):
	"""
	Creates random text samples w/ given length and enter it into the database managed in txt_learn.py
	"""
	count = 0
	for _ in range(num):
		new_sample = ''.join(random.choice(potential_chars) for _ in range(length))
		add_text_sample('_',0,new_sample)
		count += 1
	return num

def add_english_text_samples(file_names, length=std_length, quiet=False):
	"""
	Add English text samples from a list of filenames provided.
	"""
	count = 0
	for file_name in file_names:
		with open(abs_path(file_name)) as txt_file:
			full = txt_file.read()
			for ind, samp in enumerate(full[i:i+length] for i in range(0, len(full), length)):
				name = '%s_%d' % (file_name,ind)
				add_text_sample(name,1,samp)
				count += 1
	return count

def generate_dataframe(destination_file=DATAFRAME_DEST):
	"""
	Generate dataframe with data in database, pickle it, and save it in destination_file.
	"""
	e_key, v_key = 'english', 'values'
	def series_for_string(some_str, english):
		arr = arr_for_string(some_str, True)
		return pd.Series([english, arr], index=[e_key, v_key])
	df = pd.DataFrame(columns=(e_key,v_key))
	for eng, cont in get_all_samples('english, content'):
		df = df.append(series_for_string(cont, eng), ignore_index=True)
	with open(abs_path(destination_file), 'wb+') as dest: pickle.dump(df, dest)

def get_txtfile_data(text_files, length=std_length, quiet=False):
	"""
	Get english text data, supplement it with random text data, and pickle a dataframe containing all data.  Returns the number of entries created.
	"""
	count = add_english_text_samples(text_files, length, quiet=quiet)
	add_random_text_samples(count, length)
	generate_dataframe()
	return count

def main_output(count, interval):
	print("""
		Data Generation Complete
		Entries Generated: %d
		Time Elapsed: %d
		""" % (count * 2, interval))

if __name__ == '__main__':
	import sys
	import argparse
	from time import time
	beg = time()
	text_files = ['pride_and_prejudice.txt']

	parser = argparse.ArgumentParser()
	parser.add_argument('-d','--dataframe-only', action='store_true', help='Don\'t analyze text files, simply generate the dataframe from the data in the database')
	parser.add_argument('-t', '--text-only', action='store_true', help='Only split text files into chunks and enters into database for use')
	parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')
	parser.add_argument('-c', '--clear', action='store_true', help='Remove all entries from database before running program')
	parser.add_argument('-f', '--files', nargs='+', help='specify text files to use')
	args = parser.parse_args()

	if args.files: text_files = args.files

	if args.clear:
		clear_all_samples()
	if args.dataframe_only or args.text_only:
		count = -1
		if args.text_only:
			count = add_english_text_samples(text_files, quiet=args.quiet)
			add_random_text_samples(count)
		if args.dataframe_only:
			generate_dataframe()
		if count > -1 and not args.quiet: main_output(count, time() - beg)
	else:
		count = get_txtfile_data(text_files, quiet=args.quiet)
		if not args.quiet: main_output(count, time() - beg)

	