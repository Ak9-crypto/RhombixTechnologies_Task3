#(a simple example with multiple flagged issues)
# vulnerable_example.py
import os
import subprocess
import pickle
import hashlib
import requests
import sqlite3

PASSWORD = "P@ssw0rd123"  # hardcoded secret

def do_sql(user_input):
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    # insecure concatenation
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    c.execute(query)
    return c.fetchall()

def run_cmd(cmd):
    # insecure shell usage
    subprocess.Popen(cmd, shell=True)

def load_data(data):
    # insecure deserialization
    return pickle.loads(data)

def insecure_request():
    # insecure SSL verify disabled
    r = requests.get("https://example.com", verify=False)
    return r.status_code

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def use_eval(s):
    return eval(s)
