# Sniffer.py

Light weight network packet sniffer python script that is compatible with wireshark.

## Requirements
```bash
pip install -r requirements.txt
```

### Usage
```bash
usage: sniffer.py [-h] [-i INTERFACE] [-o OUTPUT] [-d DURATION] [-c COUNT] [-l]

options:
  -h, --help            show this help message and exit
  -i, --interface INTERFACE
                        Network interface to capture on
  -o, --output OUTPUT   Output PCAP file (default: capture.pcap)
  -d, --duration DURATION
                        Capture duration in seconds
  -c, --count COUNT     Number of packets to capture
  -l, --list            List available interfaces
```
