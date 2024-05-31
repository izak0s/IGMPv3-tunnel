# IGMPv3 tunnel
This project implements an IGMPv3 covert channel, a collaborative effort by Marijn, [Sam](https://github.com/samevans77), and [Isaac](https://github.com/izak0s) during the "Offensive Technologies" course at the University of Amsterdam.

This project leverages the Source Addresses field within IGMPv3 Membership Query packets (type 0x11) to encapsulate and transmit IP packets. This technique offers a potential method for concealing data transmission within network traffic.

## Getting started
### Installation
1. Clone the repository
2. Install requirements using `pip3 -r requirements.txt`

### Supported operating systems
This application is currently only supported on Linux devices.

### Example usage
Run with `--help` for help.

#### On device 1

    python3 tunnel.py -i <interface> -a <private ip (10.8.0.1)> -p <peer ip (192.168.0.2)>

#### On device 2

    python3 tunnel.py -i <interface> -a <private ip (e.g. 10.8.0.2)> -p <peer ip (e.g. 192.168.0.1)>

#### Testing
Traffic that uses the private IPs will now be encapsulated into an IGMPv3 packet and sent over the specified interface. On device 1, pinging is now:

    $ ping 10.8.0.2

Any IP traffic is encapsulated and thus not limited to a specific protocol (TCP/UDP/etc)

## License
See [LICENSE](LICENSE)