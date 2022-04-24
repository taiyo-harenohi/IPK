# IPK – Packet Sniffer in C
Nikola Machálková (xmacha80) -- 24/4/2022

A program for network analyzator, which will be able to catch and filter packets. 

## Usage
For running the program, use command 
```bash 
make
```
to create binary file. Then run this file together with the following arguments:
```bash 
./ipk-sniffer [-i \| --interface ==interface==] {-p *port*} {[--tcp\|-t] [--udp\|-u] [--arp] [--icmp] } { -n *num*}
```
The arguments' meaning is as followed:
- `-i | --interface *interface*` - interface that the program will be listening to; if there is none, it prints list of active interfaces
- `-p *port*` - filtering packets on the said port; if none, it uses every port avaiable
- `--tcp | -t` - shows only TCP packets
- `--udp | -u` - shows only UDP packets
- `--arp` - shows only ARP frames
- `--icmp` - shows only ICMPv4 and ICMPv6 packets
- `-n *num*` - defines how many packets are shown
Arguments can be in any order the user wants, there is no pre-order.

## Examples of usage: 
1. `./ipk-sniffer -i eth0 -p 23 -tcp` - Listens to TCP packets at port 23 on the eth0 interface
2. `./ipk-sniffer -i port -u` - lists out all of the avaiable interfaces
