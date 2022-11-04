# Firmware Analysis Toolkit 

FAT is a toolkit built in order to help security researchers analyze and identify vulnerabilities in IoT and embedded device firmware. This is also used in the "*[Offensive IoT Exploitation](https://www.attify-store.com/collections/training/products/offensive-iot-exploitation)*" training conducted by [Attify](https://attify.com). 

[![](https://i.ibb.co/zP9htYK/offensive-iot-exploitation-attify-embedded-hacking.png)](https://www.attify-store.com/collections/training/products/offensive-iot-exploitation)

**Note:**

+ As of now, it is simply a script to automate **[Firmadyne](https://github.com/firmadyne/firmadyne)** which is a tool used for firmware emulation. In case of any issues with the actual emulation, please post your issues in the [firmadyne issues](https://github.com/firmadyne/firmadyne/issues).  

+ In case you are facing issues, you can try [AttifyOS](https://github.com/adi0x90/attifyos) which has Firmware analysis toolkit and other tools pre-installed and ready to use.

---

Firmware Analysis Toolkit (FAT henceforth) is based on Firmadyne with some changes. Firmadyne uses a PostgreSQL database to store information about the emulated images. However just for the core functionality i.e. emulating firmware, PostgreSQL is not really needed. Hence FAT doesn't use it.

## Setup instructions 

FAT is developed in Python 3. However you need to have both Python 3 and Python 2 installed since parts of Firmadyne and its dependencies use Python 2. It's highly recommended to install FAT inside a Virtual Machine.

To install just clone the repository and run the script `./setup.sh`.

```
git clone https://github.com/attify/firmware-analysis-toolkit
cd firmware-analysis-toolkit
./setup.sh
```

After installation is completed, edit the file `fat.config` and provide the sudo password as shown below. Firmadyne requires sudo privileges for some of its operations. The sudo password is provided to automate the process.

```
[DEFAULT]
sudo_password=attify123
firmadyne_path=/home/attify/firmadyne
```

## Running FAT 

```
$ ./fat.py <firmware file>
```

+ Provide the firmware filename as an argument to the script.

+ The script would display the IP addresses assigned to the created network interfaces. Note it down.

+ Finally, it will say that running the firmware. Hit ENTER and wait until the firmware boots up. Ping the IP which was shown in the previous step, or open in the browser. 

***Congrats! The firmware is finally emulated.***

To remove all analyzed firmware images, run

```
$ ./reset.py
```

## Example 1

```
$ ./fat.py DIR-601_REVB_FIRMWARE_2.01.BIN 

                               __           _   
                              / _|         | |  
                             | |_    __ _  | |_ 
                             |  _|  / _` | | __|
                             | |   | (_| | | |_ 
                             |_|    \__,_|  \__|                    
                    
                Welcome to the Firmware Analysis Toolkit - v0.3
    Offensive IoT Exploitation Training http://bit.do/offensiveiotexploitation
                  By Attify - https://attify.com  | @attifyme
    
[+] Firmware: DIR-601_REVB_FIRMWARE_2.01.BIN
[+] Extracting the firmware...
[+] Image ID: 1
[+] Identifying architecture...
[+] Architecture: mipseb
[+] Building QEMU disk image...
[+] Setting up the network connection, please standby...
[+] Network interfaces: [('br0', '192.168.0.1')]
[+] All set! Press ENTER to run the firmware...
[+] When running, press Ctrl + A X to terminate qemu
```

**Asciicast**

[![asciicast](https://asciinema.org/a/5VryIC2ec1j9SEIfGQ0qAWjoH.svg)](https://asciinema.org/a/5VryIC2ec1j9SEIfGQ0qAWjoH)

## Example 2

```
$ ./fat.py DIR890A1_FW103b07.bin --qemu 2.5.0

                               __           _
                              / _|         | |
                             | |_    __ _  | |_
                             |  _|  / _` | | __|
                             | |   | (_| | | |_
                             |_|    \__,_|  \__|

                Welcome to the Firmware Analysis Toolkit - v0.3
    Offensive IoT Exploitation Training http://bit.do/offensiveiotexploitation
                  By Attify - https://attify.com  | @attifyme

[+] Firmware: DIR890A1_FW103b07.bin
[+] Extracting the firmware...
[+] Image ID: 2
[+] Identifying architecture...
[+] Architecture: armel
[+] Building QEMU disk image...
[+] Setting up the network connection, please standby...
[+] Network interfaces: [('br0', '192.168.0.1'), ('br1', '192.168.7.1')]
[+] Using qemu-system-arm from /home/attify/firmware-analysis-toolkit/qemu-builds/2.5.0
[+] All set! Press ENTER to run the firmware...
[+] When running, press Ctrl + A X to terminate qemu

```
## Additional Notes

- As of now, the [ARM firmadyne kernel](https://github.com/firmadyne/kernel-v4.1) doesn't work with the latest version of Qemu (2.11.1) available on the Ubuntu 18.04 official repository. However, Qemu (2.5.0) on Ubuntu 16.04 does work. Alternatively you can also use the bundled Qemu (2.5.0) provided with firmadyne as shown in example 2.

- If no network interfaces are detected, try increasing the timeout value from 60 in `scripts/inferNetwork.sh` as shown below
    ```
    echo "Running firmware ${IID}: terminating after 60 secs..."
    timeout --preserve-status --signal SIGINT 60 "${SCRIPT_DIR}/run.${ARCH}.sh" "${IID}"
    ```

## Known Issues

- ~~FAT does not work on Ubuntu 20.04. The main reason behind this is some dependencies of Firmadyne (especially binwalk) require Python 2. Unless this is fixed upstream, stick to Ubuntu 18.04 or lower.~~ 
Ubuntu 20.04 **is now supported**. The current version of FAT patches the binwalk installation script to workaround the issue.

## Building static Qemu

The repository already includes a static builds of qemu 2.0.0, 2.5.0 & 3.0.0 (in releases) but if you want to build your own follow the steps below.

On a clean **Ubuntu 16.04** VM run. (It's important to use 16.04, later versions have issues with static compilation).

### Qemu 2.0.0

```sh
sudo apt update && sudo apt build-dep qemu -y
wget https://download.qemu.org/qemu-2.0.0.tar.bz2
tar xf qemu-2.0.0.tar.bz2
mkdir qemu-2.0.0-build
cd qemu-2.0.0
./configure --prefix=$(realpath ../qemu-2.0.0-build) --static --target-list=arm-softmmu,mips-softmmu,mipsel-softmmu --disable-smartcard-nss --disable-spice --disable-libusb --disable-usb-redir
make
make install
```
The compiled binaries can be found in `qemu-2.0.0-build` directory.

### Qemu 2.5.0

```sh
sudo apt update && sudo apt build-dep qemu -y
wget https://download.qemu.org/qemu-2.5.0.tar.bz2
tar xf qemu-2.5.0.tar.bz2
mkdir qemu-2.5.0-build
cd qemu-2.5.0
./configure --prefix=$(realpath ../qemu-2.5.0-build) --static --target-list=arm-softmmu,mips-softmmu,mipsel-softmmu --disable-smartcard --disable-libusb --disable-usb-redir
make 
make install
```
The compiled binaries can be found in `qemu-2.5.0-build` directory.

### Qemu 3.0.0

```sh
sudo apt update && sudo apt build-dep qemu -y
wget https://download.qemu.org/qemu-3.0.0.tar.bz2
tar xf qemu-3.0.0.tar.bz2
mkdir qemu-3.0.0-build
cd qemu-3.0.0
./configure --prefix=$(realpath ../qemu-3.0.0-build) --static --target-list=arm-softmmu,mips-softmmu,mipsel-softmmu --disable-smartcard --disable-libusb --disable-usb-redir
make 
make install
```
The compiled binaries can be found in `qemu-3.0.0-build` directory.


Note: It should also be possible to compile qemu statically on an alpine system but this hasn't been tested. In general compiling on alpine is preferred to Ubuntu as the former comes with musl libc which is better at static linkage than glibc on Ubuntu.
