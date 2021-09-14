# gping

A simple command line ARP/TCP scanning tool.

                                           _____ _____ _____ _   _  _____ 
                                          / ____|  __ \_   _| \ | |/ ____|
                                         | |  __| |__) || | |  \| | |  __ 
                                         | | |_ |  ___/ | | | . ` | | |_ |
                                         | |__| | |    _| |_| |\  | |__| |
                                          \_____|_|   |_____|_| \_|\_____|


## About

#### gping is a command line ARP/TCP scan tool used to quickly discover devices and open ports. 
The ARP scan can be done on a single host or an entire subnet. The ARP scan will return the IP, MAC, and perform an OUI lookup of the host to determine the type of device. These results can be output to a file of your choosing This tool is in its early stages.

The TCP scan will scan a single host for designated ports, or if no ports are given then the tool will scan ports 1-1024. The results are returned with TCP flag. This tool will only send an initial SYN flag and will look for a SYN ACK in return. Known ports will be displayed as their protocal. i.e. 22 - ssh, 443 - https

## Installation

Download the `gping.py` script and
use the package manager [pip](https://pip.pypa.io/en/stable/) to install dependencies.
```bash
pip install -r requirements.txt
```
or
```bash
pip install logging
pip install scapy
pip install argparse
pip install ouilookup
pip install random
pip install datetime
```

## Usage

To use the tool, cd to the directory that contains your `gping.py` script and then run the script as shown below:
```bash
python gping.py <args>
```
or use the following for help:
```bash
python gping.py --help
```

## Pipeline
This tool will be continue to be updated, if you would like a feature please put in an issue and I will address it when available. 
Upcoming:
- UDP Scan
- XMAS Scan
- Scan formating
- Exfil via packet padding

## Contributing
If you would like to become a contributer please open an issue. For changes, please open an issue first to discuss what you would like to change.

If a you would like to commit a change, please open a pull request for review. Please make sure to update tests as appropriate.

## License
MIT License
