from test_cross_a import untrusted_data
import sqlite3

def do_query():
    cursor = sqlite3.connect('test.db').cursor()
    cursor.execute('SELECT * FROM users WHERE name = ' + untrusted_data)
