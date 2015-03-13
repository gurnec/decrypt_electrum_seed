# decrypt\_electrum\_seed.py #

 * a simple Python script which decrypts and displays the seed from an Electrum (1.x, 2.x, or an Electrum-LTC) wallet file
 * provides detailed error messages in the event of a failure
 * supported on Windows and Linux

## Warning ##

Working with an unencrypted seed is risky. If you are uncertain whether or not your computer is completely free of malware, you should not run this or any other program that can affect your finances (including Electrum).

Electrum never stores an unencrypted seed to the hard drive. You are strongly advised to follow the same practice.

## Installation ##

Just download the latest version from <https://github.com/gurnec/decrypt\_electrum\_seed/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for the Python script itself, however there are additional requirements below depending on your operating system.

### Windows ###

Visit the Python download page here: <https://www.python.org/downloads/windows/>, and click the link for the latest **Python 2** release. Download and run either the `Windows x86 MSI installer` for the 32-bit version of Python, or the `Windows x86-64 MSI installer` for the 64-bit one. If you're unsure which one is compatible with your PC, choose the 32-bit one.

### Linux ###

 * Python 2.7.x – most distributions include this pre-installed.
 * Tkinter for Python – some distributions include this pre-installed, check your distribution’s package management system to see if this is available. It is often called “python-tk”.

Before running decrypt\_electrum\_seed.py for the first time, you must enable the execute permission on the file (right click -> Properties, or use `chmod` at the command line).

## How to Use ##

Simply double-click decrypt\_electrum\_seed.py and choose your wallet file in the file selection dialog. If you're given an option between running it in a terminal or without one, choose *Run in Terminal*.

## Credits ##

Third-party libraries distributed with decrypt\_electrum\_seed.py include:

 * aespython, please see [aespython/README.txt](aespython/README.txt) for
 more information
 * Electrum 1.x mnemonic library, please see [mnemonic.py](mnemonic.py) for more information
