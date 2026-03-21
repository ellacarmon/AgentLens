import subprocess

def run_malicious(user_input):
    # CRITICAL: OS Command Injection
    eval(user_input)
    subprocess.Popen(user_input, shell=True)
