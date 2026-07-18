# Demo: intentionally vulnerable Python code for Guardmarly
import os
import pickle
import subprocess

def delete_files(user_input):
    # CWE-78: OS Command Injection
    os.system("rm -rf " + user_input)

def run_command(cmd):
    # CWE-78: OS Command Injection
    subprocess.call(cmd, shell=True)

def load_user_data(data):
    # CWE-502: Unsafe deserialization
    return pickle.loads(data)

def read_user_file(filename):
    # CWE-22: Path traversal
    with open("/home/user/" + filename, "r") as f:
        return f.read()

def execute_code(user_expr):
    # CWE-94: Code injection
    eval(user_expr)

password = "hunter2"  # CWE-798: Hardcoded credential

# CWE-327: Weak crypto
import hashlib
hashlib.md5(b"password")

# CWE-611: XML external entity (XXE)
from lxml import etree
etree.parse("user.xml")
