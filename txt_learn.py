#!/usr/local/bin/python3
"""
This module assumes the existance of a pickled file containing a pandas dataframe
at the DATFRAME_DEST.  To generate this file, use the data_generator model
"""

from data_manager import DATAFRAME_DEST, DATABASE_DEST, MODEL_DEST, abs_path
import pickle
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

#Utility Functions
from crypto import m_gen
def wrap_str(text,wrapper='`'): return ''.join((wrapper,text,wrapper))
def unwrap_str(text): return text[1:-1]
def bounded(num, lower=0, upper=1): return min(upper, max(lower, num))
def arr_for_string(s, lower=False):
	arr = np.zeros(264)
	for char in bytes(s.lower() if lower else s, encoding='utf-8'):
		arr[char] += 1
	return arr / np.sum(arr)
	
def retrieve_data(dataframe_file=DATAFRAME_DEST):
	"""
	Retrieve the X data and Y data from the stored dataframe
	"""
	with open(abs_path(dataframe_file), 'rb') as data_file: 
		df = pickle.loads(data_file.read())
		y, X = np.transpose(df.as_matrix())
		def reshaped(mat):
			mat_s = np.empty((len(mat),len(mat[0])))
			for i, row in enumerate(mat): mat_s[i] = row
			return mat_s
		X_s = reshaped(X)
		y_s = np.array(y, dtype=int)
		for i, row in enumerate(X): X_s[i] = row
		return X_s, y_s


def create_model(X, y, destination_file=MODEL_DEST):
	"""
	Create the model based on data given
	"""
	clf = LogisticRegression()
	clf.fit(X, y)
	with open(destination_file, 'wb+') as model_file: pickle.dump(clf, model_file)
	return clf

def retrieve_model(model_file=MODEL_DEST):
	"""
	Retrieve saved model
	"""
	with open(model_file, 'rb') as model_file: return pickle.load(model_file)



def predict_string(some_str, model=None):
	"""
	Returns the predicted probability
	"""
	if model is None:
		try: model = retrieve_model()
		except FileNotFoundError: model = create_model()
	str_arr = arr_for_string(some_str)
	(n, y), = model.predict_proba(str_arr.reshape(1, -1))
	return y

def run_test(X, y, mod):
	"""
	Tests accuracy of given model against given data.
	"""
	correct=[]
	for X_i, y_i in zip(X, y):
		y_p = mod.predict(X_i.reshape(1, -1))
		correct.append(y_p == y_i)
	c, t = correct.count(True), len(correct)

	print("""
	Test Complete.

	Correct: %d
	Total: %d
	Percent: %.3f
	""" % (c, t, (c / t) * 100.))

def run_interactive(mod):
	"""
	Runs command line program which predicts the probability of input strings being english based on the saved model.
	"""
	inp = lambda: input('Predict: ')
	input_string = inp()
	while len(input_string):
		prob = predict_string(input_string, mod)
		print('Estimated Probability: %.2f' % prob)
		input_string = inp()

if __name__ == '__main__':
	import argparse

	X, y = retrieve_data()
	mod = None
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--test', action='store_true', help='test model with trained data')
	parser.add_argument('-i', '--interactive', action='store_true', help='open shell which allows you to predict probabilities of strings being English text')
	parser.add_argument('-r', '--retrieve-model', action='store_true', help='instead of training model using pickled dataframe, simply retrieve the currently saved model.')

	gen_def_arg='T'
	parser.add_argument('-g', '--gen-data', nargs='?', default=gen_def_arg, help='generates data before program executes using data_generator.py.  Takes a string of one-letter command line arguments w/o hyphens followed by commas to pass to data_generator. Ex: -g q,c')
	args = parser.parse_args()
	if args.gen_data:
		file_name = 'data_generator.py'
		if args.gen_data != gen_def_arg:
			import subprocess
			g_args = ['-%s' % arg for arg in args.gen_data.split(',') if arg]
			g_argstring = ' '.join(g_args)
			subprocess.call('python3 %s %s' % (file_name, g_argstring), shell=True)
	if args.retrieve_model: mod = retrieve_model()
	else: mod = create_model(X, y) 
	if args.test: run_test(X, y, mod)
	if args.interactive: run_interactive(mod)



