from app import app
import sqlite3

conn = sqlite3.connect('database2.db')
print ("Opened database successfully")
conn.execute('CREATE TABLE teacher (teacher_name TEXT,teacher_email TEXT,team_name TEXT,student1 TEXT,student2 TEXT,student3 TEXT)')
print ("Table created successfully")
conn.close()