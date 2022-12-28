#!/usr/bin/env python3

import pexpect
import os.path
from configparser import ConfigParser

config = ConfigParser()
config.read("fat.config")

firmadyne_path = config["DEFAULT"].get("firmadyne_path", "")

sudo_pass = config["DEFAULT"].get("sudo_password", "")

print ("[+] Cleaning previous images and created files by firmadyne")

child = pexpect.spawn("/bin/sh" , ["-c", "sudo rm -rf " + os.path.join(firmadyne_path, "images/*.tar.gz")])
child.sendline(sudo_pass)
child.expect_exact(pexpect.EOF)

child = pexpect.spawn("/bin/sh", ["-c", "sudo rm -rf " + os.path.join(firmadyne_path, "scratch/*")])
child.sendline(sudo_pass)
child.expect_exact(pexpect.EOF)

print ("[+] All done. Now you can go ahead and run fat.py to continue firmware analysis")
