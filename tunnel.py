import logging
import socket
from argparse import ArgumentParser, Namespace
from threading import Thread

import psutil
import pytun
from pytun import TunTapDevice
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('IGMPv3-tunnel')


class IGMPTunnel:
    def __init__(self, args: Namespace):
        self.args = args
        self.threads = []
        self.tun = TunTapDevice(name=args.tun, flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        self.running = False

    def start(self):
        """ Start the IGMPv3 tunnel """
        if self.running:
            log.error("Failed to start tunnel, tunnel is already running!")
            return

        self.running = True
        self._setup_tunnel()
        self._setup_thread()

    def _setup_tunnel(self):
        """ Construct the TUN/TAP device """
        self.tun.addr = self.args.addr
        self.tun.netmask = '255.255.255.0'
        self.tun.mtu = 1450
        self.tun.up()

    def _setup_thread(self):
        """ Setup sender/receiver threads """
        self.threads = [
            Thread(target=self._sender),
            Thread(target=self._receiver),
        ]

        # Start threads
        [t.start() for t in self.threads]
        # Join threads
        [t.join() for t in self.threads]

    def close(self):
        """ Gracefully close tunnel """
        log.info("Closing tunnel")
        self.running = False

        self.tun.down()
        self.tun.close()

        log.info("Waiting for threads to stop")

    def _sender(self):
        """ Reads packets from the TUN/TAP device and encapsulates it into IGMPv3 packets """
        with socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw_socket:
            log.info(
                f"Waiting for out packets on {self.args.tun} ({self.args.addr}) -> sending IGMPv3 packets to {self.args.peer}")
            raw_socket.bind((self.args.interface, socket.htons(0x0800)))
            igmp_base = (
                    Ether() / IP(dst=self.args.peer, ttl=10) /
                    IGMPv3(type=0x11) /
                    IGMPv3mq(resv=11, s=0, qrv=0, qqic=0, numsrc=0, srcaddrs=[])
            ).build()

            while self.running:
                buf = self.tun.read(self.tun.mtu)

                size = len(buf) // 4

                # Slower build method with size calculation
                if not self.args.efficient:
                    built_packet = (
                            Ether() / IP(dst=self.args.peer, ttl=10) /
                            (IGMPv3(type=0x11) /
                             IGMPv3mq(resv=11, s=0, qrv=0, qqic=0, numsrc=size) /
                             Raw(buf)
                             )
                    ).build()
                else:
                    # Construct packet
                    built_packet = igmp_base + buf

                try:
                    raw_socket.send(built_packet)
                except OSError as e:
                    log.error("Something went wrong while sending packet :(", built_packet, e)

    def _receiver(self):
        """ Reads IGMPv3 packets from network, transforms into normal packets, written to TUN/TAP device """
        with socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw_socket:
            log.info("Waiting for incoming IGMPv3 packets")
            while self.running:
                # Receive packet from socket
                pkt, _ = raw_socket.recvfrom(1500)

                # Filter non-igmp packets (2=IGMP)
                if pkt[23] != 2:
                    continue

                # Match the reserved fields
                if pkt[42] != 176:
                    continue

                # Extract payload from packet
                payload = pkt[46:]

                # Send normal IP packet to TUN device
                self.tun.write(payload)


def parse_arguments():
    available_interfaces = psutil.net_if_addrs()

    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", type=str, choices=available_interfaces.keys(), required=True,
                        help="The sending/receiving interface for IGMPv3 packets")
    parser.add_argument("-t", "--tun", type=str, default="IGMP_tunnel", help="The name of the TUN NIC")
    parser.add_argument("-a", "--addr", type=str, required=True,
                        help="The private IP address associated to this device (e.g. 10.8.0.1)")
    parser.add_argument("-p", "--peer", type=str, required=True,
                        help="The IGMPv3 reachable IP address of the peer to send IGMPv3 packets to (e.g. 192.168.x.x)")
    parser.add_argument("-e", "--efficient", default=False, action="store_true",
                        help="Use the IGMPv3 covert channel that sets the number of sources to zero, improves bitrate "
                             "but could raise alerts")

    return parser.parse_args()


def main():
    args = parse_arguments()
    tunnel = IGMPTunnel(args)
    try:
        tunnel.start()
    except KeyboardInterrupt:
        log.info("Interrupting")
    finally:
        tunnel.close()


if __name__ == '__main__':
    main()