from flask import request
import subprocess

def vuln():
    host = request.form.get("host")
    # ruleid: test_rule
    subprocess.check_output("ping -c 1 " + host, shell=True)

def safe():
    # ok: test_rule
    subprocess.check_output("ping 127.0.0.1", shell=True)