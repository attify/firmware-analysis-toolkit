#!/usr/bin/env python2.7

import os
import pexpect
import sys
import subprocess

# Put this script in the firmadyne path downloadable from
# https://github.com/firmadyne/firmadyne

#Configurations - change this according to your system
firmadyne_path = "/home/ec/firmadyne"
binwalk_path = "/usr/local/bin/binwalk"
root_pass = "root"
firmadyne_pass = "firmadyne"


def show_banner():
    print """
                               __           _   
                              / _|         | |  
                             | |_    __ _  | |_ 
                             |  _|  / _` | | __|
                             | |   | (_| | | |_ 
                             |_|    \__,_|  \__|                    
                    
                Welcome to the Firmware Analysis Toolkit - v0.2
    Offensive IoT Exploitation Training  - http://offensiveiotexploitation.com
                  By Attify - https://attify.com  | @attifyme
    """


def get_info():
    if len(sys.argv) == 2:
        firm_name = sys.argv[1]
        print "[?] Enter the name or absolute path of the firmware you want to analyse : " + firm_name
    else:
        firm_name = raw_input("[?] Enter the name or absolute path of the firmware you want to analyse : ")
    firm_brand = raw_input("[?] Enter the brand of the firmware : ")
    return (firm_name, firm_brand)


def run_extractor(firm_name, firm_brand):
    print "[+] Now going to extract the firmware. Hold on.."
    print "[+] Firmware : " + firm_name
    print "[+] Brand : " + firm_brand
    extractor_cmd = firmadyne_path + "/sources/extractor/extractor.py -b " + firm_brand + " -sql 127.0.0.1 -np -nk " + "\""+ firm_name + "\"" + " images "
    child = pexpect.spawn(extractor_cmd, timeout=None)
    child.expect("Database Image ID: ")
    image_id = child.readline().strip()
    print "[+] Database image ID : " + image_id
    child.expect(pexpect.EOF)
    return image_id


def identify_arch(image_id):
    print "[+] Identifying architecture"
    identfy_arch_cmd = firmadyne_path + "/scripts/getArch.sh ./images/" + image_id + ".tar.gz"
    child = pexpect.spawn(identfy_arch_cmd)
    child.expect(":")
    arch = child.readline().strip()
    print "[+] Architecture : " + arch
    child.expect("Password for user firmadyne: ")    
    child.sendline(firmadyne_pass)
    child.expect(pexpect.EOF)
    return arch


def tar2db(image_id):
    print "[+] Storing filesystem in database"
    tar2db_cmd = firmadyne_path + "/scripts/tar2db.py -i " + image_id + " -f " + firmadyne_path + "/images/" + image_id + ".tar.gz"
    output_tar2db = pexpect.run(tar2db_cmd)

    if "already exists" in output_tar2db:
        print "[!] Filesystem already exists"


def make_image(arch, image_id):
    print "[+] Building QEMU disk image"
    makeimage_cmd = "sudo " + firmadyne_path + "/scripts/makeImage.sh " + image_id + " " + arch
    child = pexpect.spawn(makeimage_cmd)
    child.sendline(root_pass)
    child.expect(pexpect.EOF)


def setup_network(arch, image_id):
    print "[+] Setting up the network connection, please standby"
    network_cmd = "sudo " + firmadyne_path + "/scripts/inferNetwork.sh " + image_id + " " + arch
    child = pexpect.spawn(network_cmd)
    child.sendline(root_pass)
    child.expect("Interfaces:", timeout=None)
    interfaces = child.readline().strip()
    print "[+] Network interfaces : " + interfaces
    child.expect(pexpect.EOF)


def final_run(image_id):
    print "[+] Running the firmware finally"
    run_cmd = "sudo " + firmadyne_path + "/scratch/" + image_id + "/run.sh"
    print "[+] command line : " + run_cmd
    raw_input("[*] Press ENTER to run the firmware...")
    child = pexpect.spawn(run_cmd)
    child.sendline(root_pass)
    child.interact()    


def main():
    show_banner()
    firm_name, firm_brand = get_info()
    image_id = run_extractor(firm_name, firm_brand)
    
    if image_id == "":
        print "[!] Something went wrong"
    else:
        arch = identify_arch(image_id)        
        tar2db(image_id)
        make_image(arch, image_id)        
        setup_network(arch, image_id)        
        final_run(image_id)


if __name__ == "__main__":
    main()