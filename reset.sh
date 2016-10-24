#!/bin/bash

echo -e "\e[1m[+] Deleting existing database with the name firmware\n"
psql -d postgres -U firmadyne -h 127.0.0.1 -q -c 'DROP DATABASE "firmware"'

echo -e "\n [+] Creating new database with firmware with the user firmadyne" 
sudo -u postgres createdb -O firmadyne firmware

echo -e "\n [+] Making necessary changes to the db" 
sudo -u postgres psql -d firmware < ./database/schema

echo -e "\n [+] Cleaning previous images and created files by firmadyne"
sudo rm -rf ./images/*.tar.gz
sudo rm -rf scratch/

echo -e """ \e[32m[+] All done. Go ahead and run fat.py to continue firmware analysis
     \n Remember the password for the database is \e[31mfirmadyne"""

