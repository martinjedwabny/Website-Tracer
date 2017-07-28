### Dependencies
* `sudo apt-get install python-pygraphviz`
* `sudo apt-get install geoip-bin`
* `sudo pip install networkx`
* `sudo pip install scapy`
* `sudo pip install scipy`

### Usage
Executing `sudo ./traceroute.py <IP> -d` will:
- Perform 50 normal traceroutes
- Calculate the usual path to the ip
- Calculate the average time to get to the ip
- Obtains geolocalizations of the path using ipinfo.io
