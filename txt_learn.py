#!/usr/local/bin/python3

import sqlite3

#Utility Functions
from crypto import m_gen
def wrap_str(text,wrapper='\''): return ''.join((wrapper,text,wrapper))
def unwrap_str(text): return text[1:-1]

with sqlite3.connect("english-text.db") as conn:
	# Managing the Databse
	curs = conn.cursor()
	curs.execute("""
		CREATE TABLE IF NOT EXISTS all_data (
			id	INTEGER	PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			english INT,
			content TEXT
		)
		""")

	def run_query(query): curs.execute(query)

	def add_text_sample(name,english,content):
		"""
		Add a row the to table w/ values provided
		"""
		run_query("""
			INSERT INTO all_data (name, english, content) VALUES (%s,%d,%s)
			""" % (wrap_str(name), int(english), wrap_str(content)))
		conn.commit()

	def get_all_samples(fields='*'):
		"""
		Retrieve all rows of the table.  May specify a string to use for as indexes i.e. (name, english, content)
		"""
		run_query("""
			SELECT %s FROM all_data
			""" % fields)
		return curs.fetchall()

