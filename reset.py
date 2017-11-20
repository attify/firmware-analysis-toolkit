#!/usr/bin/env python2.7

import sys
import pexpect

# Change the root password according to your system
root_pass = "root"
firm_pass = "firmadyne"

print
print "[+] Deleting existing database with the name firmware"
child = pexpect.spawn("psql -d postgres -U firmadyne -h 127.0.0.1 -q -c 'DROP DATABASE \"firmware\"'")
child.expect("Password for user firmadyne: ")
child.sendline(firm_pass)
child.expect(pexpect.EOF)

print "[+] Creating new database with firmware with the user firmadyne" 
child = pexpect.spawn("sudo -u postgres createdb -O firmadyne firmware")
child.sendline(root_pass)
child.expect(pexpect.EOF)

print "[+] Making necessary changes to the db" 
child = pexpect.spawn("/bin/sh", ["-c", "sudo -u postgres psql -d firmware < ./database/schema"])
child.sendline(root_pass)
child.expect(pexpect.EOF)

print "[+] Cleaning previous images and created files by firmadyne"
child = pexpect.spawn("/bin/sh", ["-c", "sudo rm -rf ./images/*.tar.gz"])
child.sendline(root_pass)
child.expect(pexpect.EOF)

child = pexpect.spawn("sudo rm -rf scratch/")
child.sendline(root_pass)
child.expect(pexpect.EOF)
print "[+] All done. Go ahead and run fat.py to continue firmware analysis"
print "    Remember the password for the database is firmadyne\n"

