#!/usr/bin/local/python3

import sqlite3

DATA_FOLDER = 'data'
def abs_path(filename): return '%s/%s' % (DATA_FOLDER, filename)
DATAFRAME_DEST = 'dataframe.pkl'
MODEL_DEST = 'model.pkl'
DATABASE_DEST = 'english-text.db'

from txt_learn import wrap_str

with sqlite3.connect(abs_path(DATABASE_DEST)) as conn:
	# Managing the Databse
	curs = conn.cursor()
	
	def __maketable(cursor):
		cursor.execute("""
		CREATE TABLE IF NOT EXISTS all_data (
			id	INTEGER	PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			english INT,
			content TEXT
		)
		""")
	
	__maketable(curs)

	def run_query(query, vals=None, quiet=False): 
		try: 
			if vals: curs.execute(query, vals)
			else: curs.execute(query)
		except: 
			if not quiet: print('Query Failed: %s' % query)

	def add_text_samples(*args, quiet=False):
		"""
		Adds rows w/ values provided in each argument, 3-tuple formatted as (name, english, content)
		"""
		for name, english, content in args:
			run_query("""
				INSERT INTO all_data (name, english, content) VALUES (?,?,?)
				""", (wrap_str(name), int(english), wrap_str(content)), quiet=quiet)
		conn.commit()

	def add_text_sample(name,english,content, quiet=False):
		"""
		Add a single row w/ values provided
		"""
		add_text_samples((name,english,content), quiet=quiet)

	def get_all_samples(fields='*', quiet=False):
		"""
		Retrieve all rows of the table.  May specify a string to use for as indexes i.e. (name, english, content)
		"""
		run_query("""
			SELECT %s FROM all_data
			""" % fields, quiet=quiet)
		return curs.fetchall()

	def clear_all_samples(quiet=False):
		"""
		Clear all samples currently held in database
		"""
		run_query("""
			DELETE FROM all_data
			""", quiet=quiet)
		conn.commit()