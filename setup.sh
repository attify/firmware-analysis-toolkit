#!/bin/sh

set -e
sudo apt update
sudo apt install -y python3-pip python3-pexpect unzip busybox-static fakeroot kpartx snmp uml-utilities util-linux vlan qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils wget tar

if [ ! -x "$(which lsb_release)" ]
then
    sudo apt install -y lsb-core
fi

echo "Installing binwalk"
git clone --depth=1 https://github.com/ReFirmLabs/binwalk.git
cd binwalk

# Temporary fix for sasquatch failing to install (From https://github.com/ReFirmLabs/binwalk/pull/601)
sed -i 's;\$SUDO ./build.sh;wget https://github.com/devttys0/sasquatch/pull/47.patch \&\& patch -p1 < 47.patch \&\& \$SUDO ./build.sh;' deps.sh

# Change to python3 in deps.sh to allow installation on Ubuntu 20.04 (binwalk commit 2b78673)
sed -i '/REQUIRED_UTILS="wget tar python"/c\REQUIRED_UTILS="wget tar python3"' deps.sh
sudo ./deps.sh --yes
sudo python3 ./setup.py install
sudo -H pip3 install git+https://github.com/ahupp/python-magic
sudo -H pip3 install git+https://github.com/sviehb/jefferson
cd ..

echo "Installing firmadyne"
# tested with firmadyne commit bcd8bc0
git clone --recursive https://github.com/firmadyne/firmadyne.git
cd firmadyne
./download.sh
firmadyne_dir=$(realpath .)

# Set FIRMWARE_DIR in firmadyne.config
sed -i "/FIRMWARE_DIR=/c\FIRMWARE_DIR=$firmadyne_dir" firmadyne.config

# Comment out psql -d firmware ... in getArch.sh
sed -i 's/psql/#psql/' ./scripts/getArch.sh

# Change interpreter to python3
sed -i 's/env python/env python3/' ./sources/extractor/extractor.py ./scripts/makeNetwork.py
cd ..

echo "Setting up firmware analysis toolkit"
chmod +x fat.py
chmod +x reset.py

# Set firmadyne_path in fat.config
sed -i "/firmadyne_path=/c\firmadyne_path=$firmadyne_dir" fat.config

cd qemu-builds

wget -O qemu-system-static-2.0.0.zip "https://github.com/attify/firmware-analysis-toolkit/files/9937453/qemu-system-static-2.0.0.zip"
unzip -qq qemu-system-static-2.0.0.zip && rm qemu-system-static-2.0.0.zip

wget -O qemu-system-static-2.5.0.zip "https://github.com/attify/firmware-analysis-toolkit/files/4244529/qemu-system-static-2.5.0.zip"
unzip -qq qemu-system-static-2.5.0.zip && rm qemu-system-static-2.5.0.zip

wget -O qemu-system-static-3.0.0.tar.gz "https://github.com/attify/firmware-analysis-toolkit/files/9937487/qemu-system-static-3.0.0.tar.gz"
tar xf qemu-system-static-3.0.0.tar.gz && rm qemu-system-static-3.0.0.tar.gz

cd ..

echo "====================================================="
echo "Firmware Analysis Toolkit installed successfully!"
echo "Before running fat.py for the first time,"
echo "please edit fat.config and provide your sudo password"
echo "====================================================="
