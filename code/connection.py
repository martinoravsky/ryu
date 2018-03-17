import mysql

def connect():
    conn = mysql.connector.connect(host='192.168.56.105',
								    database='mptcp',
									user='mptcp',
									password='mptcp123')
    return conn