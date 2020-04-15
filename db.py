from app import app
import sqlite3

conn = sqlite3.connect('database.db')
print ("Opened database successfully")
'''cur = conn.execute('SELECT * FROM users')
data = cur.fetchall()
print(data)'''
#conn.execute('DROP TABLE users')
conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,user_name TEXT,user_email TEXT,user_password TEXT)')
print ("Table created successfully")

#conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,user_name TEXT,user_email TEXT,user_password TEXT)')
#print ("Table created successfully")
conn.close()
