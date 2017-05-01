#!/bin/bash -x
# Install on Debian Live

sudo apt-get install python-dev libusb-1.0-0-dev libudev-dev python-pip git
sudo pip install --upgrade setuptools
git clone https://github.com/trezor/cython-hidapi.git
cd cython-hidapi
git submodule update --init
python setup.py build
sudo python setup.py install
cd..
pip install ledgerblue
