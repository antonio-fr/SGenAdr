#!/bin/bash -x
# Install SGenAdr on Debian Live
# run with : sudo bash -x debian-install.sh

apt-get -y install python-dev libusb-1.0-0-dev libudev-dev python-pip git
pip install --upgrade setuptools
git clone https://github.com/trezor/cython-hidapi.git
cd cython-hidapi
git submodule update --init
python setup.py build
python setup.py install
cd..
pip install ledgerblue
