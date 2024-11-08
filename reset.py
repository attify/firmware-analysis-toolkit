#!/usr/bin/env python3

import pexpect
import os.path
from configparser import ConfigParser

config = ConfigParser()
config.read("fat.config")
firmadyne_path = config["DEFAULT"].get("firmadyne_path", "")
sudo_pass = config["DEFAULT"].get("sudo_password", "")

print ("[+] Checking if filesystem is still mounted...")
child = pexpect.spawn("/bin/sh" , ["-c", "sudo findmnt -l | grep " + os.path.join(firmadyne_path, "scratch/*/image")])
child.sendline(sudo_pass)
child.expect_exact(pexpect.EOF)
if bytes(firmadyne_path.encode()) in child.before:
    loop_dev = child.before.split(b' ')[1].decode()
    print ("[+] Unmounting filesystem...")
    child = pexpect.spawn("/bin/sh" , ["-c", "sudo umount " + loop_dev])
    child.sendline(sudo_pass)
    child.expect_exact(pexpect.EOF)

print ("[+] Cleaning previous images and created files by firmadyne")
child = pexpect.spawn("/bin/sh" , ["-c", "sudo rm -rf " + os.path.join(firmadyne_path, "images/*.tar.gz")])
child.sendline(sudo_pass)
child.expect_exact(pexpect.EOF)

child = pexpect.spawn("/bin/sh", ["-c", "sudo rm -rf " + os.path.join(firmadyne_path, "scratch/*")])
child.sendline(sudo_pass)
child.expect_exact(pexpect.EOF)
print ("[+] All done. Go ahead and run fat.py to continue firmware analysis")
