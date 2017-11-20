# Firmware Analysis Toolkit 

FAT is a toolkit built in order to help security researchers analyze and identify vulnerabilities in IoT and embedded device firmware. This is built in order to use for the "*[Offensive IoT Exploitation](http://offensiveiotexploitation.com/)*" training conducted by [Attify](https://attify.com). 

_**Download AttifyOS**_

[![AttifyOS download](https://i.ytimg.com/vi/nQdrVTcAPkI/hqdefault.jpg)](https://www.youtube.com/watch?v=nQdrVTcAPkI "Setting up AttifyOS")

**Note:** 

+ As of now, it is simply a script to automate **[Firmadyne](https://github.com/firmadyne/firmadyne)** which is a tool used for firmware emulation. In case of any issues with the actual emulation, please post your issues in the [firmadyne issues](https://github.com/firmadyne/firmadyne/issues).  

+ In case you are on **Kali** and are **facing issues with emulation**, it is recommended to use the AttifyOS Pre-Release VM downloadable from [here](http://tinyurl.com/attifyos), or alternatively you could do the above mentioned.  

---

Firmware Analysis Toolkit is build on top of the following existing tools and projects : 

1. [Firmadyne](https://github.com/firmadyne/firmadyne)
2. [Binwalk](https://github.com/devttys0/binwalk) 
3. [Firmware-Mod-Kit](https://github.com/mirror/firmware-mod-kit)
4. [MITMproxy](https://mitmproxy.org/) 
5. [Firmwalker](https://github.com/craigz28/firmwalker) 

## Setup instructions 

If you are a training student and setting this as a pre-requirement for the training, it is recommended to install the tools in the /root/tools folder, and individual tools in there. 

### Install Binwalk 

```
git clone https://github.com/devttys0/binwalk.git
cd binwalk
sudo ./deps.sh
sudo python ./setup.py install
sudo apt-get install python-lzma  :: (for Python 2.x) 
sudo -H pip install git+https://github.com/ahupp/python-magic
```

Note: Alternatively, you could also do a `sudo apt-get install binwalk`


### Setting up firmadyne 

`sudo apt-get install busybox-static fakeroot git kpartx netcat-openbsd nmap python-psycopg2 python3-psycopg2 snmp uml-utilities util-linux vlan qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils`

`git clone --recursive https://github.com/firmadyne/firmadyne.git`

`cd ./firmadyne; ./download.sh`

Edit `firmadyne.config` and make the `FIRMWARE_DIR` point to the current location of Firmadyne folder. 

### Setting up Firmware Analysis Toolkit (FAT)

First install [`pexpect`](https://github.com/pexpect/pexpect).

```
pip install pexpect
```
Now clone the repo to your system.
```
git clone https://github.com/attify/firmware-analysis-toolkit
mv firmware-analysis-toolkit/fat.py .
mv firmware-analysis-toolkit/reset.py .
chmod +x fat.py 
chmod +x reset.py
```

Adjust the paths to firmadyne and binwalk in `fat.py` and `reset.py`. Additionally, provide the root password. Firmadyne requires root privileges for some of its operations. The root password is provided in the script itself to automate the process.

```python
# Configurations - change this according to your system
firmadyne_path = "/home/ec/firmadyne"
binwalk_path = "/usr/local/bin/binwalk"
root_pass = "root"
firmadyne_pass = "firmadyne"
```

### Setting up Firmware-mod-Kit 

```
sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic
git clone https://github.com/brianpow/firmware-mod-kit.git
```

Find the location of binwalk using `which binwalk` . Modify the file `shared-ng.inc` to change the value of variable `BINWALK` to the value of `/usr/local/bin/binwalk` (if that is where your binwalk is installed). . 

### Setting up MITMProxy 

`pip install mitmproxy` 
or 
`apt-get install mitmproxy` 

### Setting up Firmwalker 

`git clone https://github.com/craigz28/firmwalker.git` 

That is all the setup needed in order to run FAT. 

## Running FAT 

Once you have completed the above steps you can run can fat. The syntax for running fat is


```
$ python fat.py <firmware file>
```

+ Provide the firmware filename as an argument to the script. If not provided, the script would prompt for it at runtime.

+ The script will then ask you to enter the brand name. Enter the brand which the firmware belongs to. This is for pure database storage and categorisational purposes. 

+ The script would display the IP addresses assigned to the created network interfaces. Note it down.

+ Finally, it will say that running the firmware. Hit ENTER and wait until the firmware boots up. Ping the IP which was shown in the previous step, or open in the browser. 

***Congrats! The firmware is finally emulated. The next step will be to setup the proxy in Firefox and run mitmproxy.***

To remove all analyzed firmware images, run

```
$ python reset.py
```
### Example Run

```
$ python fat.py DIR850LB1_FW210WWb03.bin 

                               __           _   
                              / _|         | |  
                             | |_    __ _  | |_ 
                             |  _|  / _` | | __|
                             | |   | (_| | | |_ 
                             |_|    \__,_|  \__|                    
                    
                Welcome to the Firmware Analysis Toolkit - v0.2
    Offensive IoT Exploitation Training  - http://offensiveiotexploitation.com
                  By Attify - https://attify.com  | @attifyme
    
[?] Enter the name or absolute path of the firmware you want to analyse : DIR850LB1_FW210WWb03.bin
[?] Enter the brand of the firmware : dlink
[+] Now going to extract the firmware. Hold on..
[+] Firmware : DIR850LB1_FW210WWb03.bin
[+] Brand : dlink
[+] Database image ID : 1
[+] Identifying architecture
[+] Architecture : mipseb
[+] Storing filesystem in database
[!] Filesystem already exists
[+] Building QEMU disk image
[+] Setting up the network connection, please standby
[+] Network interfaces : [('br0', '192.168.0.1'), ('br1', '192.168.7.1')]
[+] Running the firmware finally
[+] command line : sudo /home/ec/firmadyne/scratch/1/run.sh
[*] Press ENTER to run the firmware...
```
