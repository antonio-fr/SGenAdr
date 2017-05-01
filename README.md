  SGenAdr
===========

SGenAdr is a secure Bitcoin address generator.
For secured random source for key generation, it can use the AIS-31 Class PTG.2 compliant true random number generator (TRNG) from Ledger the Ledger Nano S.

NanoS is optional.

## Install

### Linux
**Requirements:**
- setuptools / g++ and make
- libudev-dev / systemd-devel
- libusb-1.0-0-dev / libusb-devel
- python2.7-dev(el)

Finally :

    pip install ledgerblue

For a full and quick install on Debian, you can use install bash script included:

    sudo bash -x debian-install.sh


If you want to use SGenAdr **with a non-root user** and the NanoS, create a file */etc/udev/rules.d/20-nanos.rules* containing :
```
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0000", MODE="0660", TAG+="uaccess", TAG+="udev-acl", OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0001", MODE="0660", TAG+="uaccess", TAG+="udev-acl", OWNER="<UNIX username>"
```
Then restart udev (or just reboot the machine):

    udevadm trigger


### Windows :

**Requirements :**
- Python2.7
- Visual C++ Compiler for Python 2.7
https://www.microsoft.com/en-us/download/details.aspx?id=44266

Finally in an Administrator CMD :

    pip install ledgerblue


## Usage

    python SGenAdr.py <Number of Adresses to Generate>

If you have a Nano S, connect it and enter PIN (do not enter in any app).

Follow the instructions displayed during run.


## Output

2 files are generated :
- A CSV file with *index, pubkey, address*
- A JSON-like file with the private keys in WIF. 

