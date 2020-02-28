#!/usr/bin/env python3

import os
import os.path
import pexpect
import sys
import argparse

from configparser import ConfigParser

config = ConfigParser()
config.read("fat.config")
firmadyne_path = config["DEFAULT"].get("firmadyne_path", "")
sudo_pass = config["DEFAULT"].get("sudo_password", "")


def show_banner():
    print ("""
                               __           _
                              / _|         | |
                             | |_    __ _  | |_
                             |  _|  / _` | | __|
                             | |   | (_| | | |_
                             |_|    \__,_|  \__|

                Welcome to the Firmware Analysis Toolkit - v0.3
    Offensive IoT Exploitation Training http://bit.do/offensiveiotexploitation
                  By Attify - https://attify.com  | @attifyme
    """)


def get_next_unused_iid():
    for i in range(1, 1000):
        if not os.path.isdir(os.path.join(firmadyne_path, "scratch", str(i))):
            return str(i)
    return ""


def run_extractor(firm_name):
    print ("[+] Firmware:", os.path.basename(firm_name))
    print ("[+] Extracting the firmware...")

    extractor_cmd = os.path.join(firmadyne_path, "sources/extractor/extractor.py")
    extractor_args = [
        "-np",
        "-nk",
        firm_name,
        os.path.join(firmadyne_path, "images")
    ]

    child = pexpect.spawn(extractor_cmd, extractor_args, timeout=None)
    child.expect_exact("Tag: ")
    tag = child.readline().strip().decode("utf8")
    child.expect_exact(pexpect.EOF)

    image_tgz = os.path.join(firmadyne_path, "images", tag + ".tar.gz")

    if os.path.isfile(image_tgz):
        iid = get_next_unused_iid()
        if iid == "" or os.path.isfile(os.path.join(os.path.dirname(image_tgz), iid + ".tar.gz")):
            print ("[!] Too many stale images")
            print ("[!] Please run reset.py or manually delete the contents of the scratch/ and images/ directory")
            return ""

        os.rename(image_tgz, os.path.join(os.path.dirname(image_tgz), iid + ".tar.gz"))
        print ("[+] Image ID:", iid)
        return iid

    return ""


def identify_arch(image_id):
    print ("[+] Identifying architecture...")
    identfy_arch_cmd = os.path.join(firmadyne_path, "scripts/getArch.sh")
    identfy_arch_args = [
        os.path.join(firmadyne_path, "images", image_id + ".tar.gz")
    ]
    child = pexpect.spawn(identfy_arch_cmd, identfy_arch_args, cwd=firmadyne_path)
    child.expect_exact(":")
    arch = child.readline().strip().decode("utf8")
    print ("[+] Architecture: " + arch)
    child.expect_exact(pexpect.EOF)
    return arch


def make_image(arch, image_id):
    print ("[+] Building QEMU disk image...")
    makeimage_cmd = os.path.join(firmadyne_path, "scripts/makeImage.sh")
    makeimage_args = ["--", makeimage_cmd, image_id, arch]
    child = pexpect.spawn("sudo", makeimage_args, cwd=firmadyne_path)
    child.sendline(sudo_pass)
    child.expect_exact(pexpect.EOF)


def infer_network(arch, image_id, qemu_dir):
    print ("[+] Setting up the network connection, please standby...")
    network_cmd = os.path.join(firmadyne_path, "scripts/inferNetwork.sh")
    network_args = [image_id, arch]

    if qemu_dir:
        path = os.environ["PATH"]
        newpath = qemu_dir + ":" + path
        child = pexpect.spawn(network_cmd, network_args, cwd=firmadyne_path, env={"PATH":newpath})
    else:
        child = pexpect.spawn(network_cmd, network_args, cwd=firmadyne_path)

    child.expect_exact("Interfaces:", timeout=None)
    interfaces = child.readline().strip().decode("utf8")
    print ("[+] Network interfaces:", interfaces)
    child.expect_exact(pexpect.EOF)


def final_run(image_id, arch, qemu_dir):
    runsh_path = os.path.join(firmadyne_path, "scratch", image_id, "run.sh")
    if not os.path.isfile(runsh_path):
        print ("[!] Cannot emulate firmware, run.sh not generated")
        return
    
    if qemu_dir:
        if arch == "armel":
            arch = "arm"
        elif arch == "mipseb":
            arch = "mips"
        print ("[+] Using qemu-system-{0} from {1}".format(arch, qemu_dir))
        cmd = 'sed -i "/QEMU=/c\QEMU={0}/qemu-system-{1}" "{2}"'.format(qemu_dir, arch, runsh_path)
        pexpect.run(cmd)

    print ("[+] All set! Press ENTER to run the firmware...")
    input ("[+] When running, press Ctrl + A X to terminate qemu")

    print ("[+] Command line:", runsh_path)
    run_cmd = ["--", runsh_path]
    child = pexpect.spawn("sudo", run_cmd, cwd=firmadyne_path)
    child.sendline(sudo_pass)
    child.interact()


def main():
    show_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("firm_path", help="The path to the firmware image", type=str)
    parser.add_argument("-q", "--qemu", metavar="qemu_path", help="The qemu version to use (must exist within qemu-builds directory). If not specified, the qemu version installed system-wide will be used", type=str)
    args = parser.parse_args()

    qemu_ver = args.qemu
    qemu_dir = None
    if qemu_ver:
        qemu_dir = os.path.abspath(os.path.join("qemu-builds", qemu_ver))
        if not os.path.isdir(qemu_dir):
            print ("[!] Directory {0} not found".format(qemu_dir))
            print ("[+] Using system qemu")
            qemu_dir = None

    image_id = run_extractor(args.firm_path)

    if image_id == "":
        print ("[!] Image extraction failed")
    else:
        arch = identify_arch(image_id)
        make_image(arch, image_id)
        infer_network(arch, image_id, qemu_dir)
        final_run(image_id, arch, qemu_dir)


if __name__ == "__main__":
    main()
