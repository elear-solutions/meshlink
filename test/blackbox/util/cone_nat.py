#!/usr/bin/python

# This needs to be run as root.
# It manages the FORWARD table.
# Make sure you have SNAT and DNAT rules set up in the nat table.

import struct
import sys
import time
import subprocess
import os
import select
import argparse
import nflog
import signal
import netifaces
import random
import daemon

from socket import AF_INET, inet_ntoa, inet_aton
from dpkt import ip

verbose = False

# Port mapping state
mapping = {}

# Parse command line option
parser = argparse.ArgumentParser(description="Poor man's cone NAT simulator")
parser.add_argument('--type', choices=['full', 'address', 'port', 'symmetric'], help='The type of cone NAT to simulate. Default: address', default='port')
parser.add_argument('--timeout', type=int, help='The timeout for NAT mappings in seconds. Default: 180', default=180)
parser.add_argument('--wan', type=str, help='The WAN interface. Default: eth0', default='eth0')
parser.add_argument('--lan', type=str, help='The LAN interface. Default: eth1', default='eth1')
parser.add_argument('-d', '--daemon', action='store_true', help='Run in the background after setting up the initial rules')
parser.add_argument('-v', '--verbose', action='store_true', help='Print debug messages')
args = parser.parse_args()

if args.verbose:
    verbose = True

wan_ip = netifaces.ifaddresses(args.wan)[netifaces.AF_INET][0]['addr']

# Set up the FORWARD chain
assert 0 == subprocess.call(['iptables', '-F', 'FORWARD', '-w']) # Flush existing rules
assert 0 == subprocess.call(['iptables', '-P', 'FORWARD', 'DROP', '-w']) # Default policy deny
assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-i', args.lan, '-o', args.wan, '-p', 'udp', '-j', 'NFLOG', '-w']) # Log outgoing packets
assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-i', args.lan, '-o', args.wan, '-p', 'tcp', '-j', 'ACCEPT', '-w']) # Allow TCP
assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-i', args.wan, '-o', args.lan, '-p', 'tcp', '-j', 'ACCEPT', '-w']) # Allow TCP
assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-p', 'icmp', '-j', 'ACCEPT', '-w']) # Allow ICMP

# Set up the nat table
assert 0 == subprocess.call(['iptables', '-t', 'nat', '-F', 'PREROUTING', '-w']) # Flush existing rules
assert 0 == subprocess.call(['iptables', '-t', 'nat', '-F', 'POSTROUTING', '-w']) # Flush existing rules
assert 0 == subprocess.call(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-p', 'tcp', '-o', args.wan, '-j', 'MASQUERADE', '-w'])
assert 0 == subprocess.call(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-p', 'icmp', '-o', args.wan, '-j', 'MASQUERADE', '-w'])

# Flush the connection tracking table, it might contain old entries
subprocess.call(["conntrack", "-D", "-p", "udp"])

if args.type == 'symmetric':
    assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-i', args.lan, '-o', args.wan, '-j', 'ACCEPT', '-w']) # Accept outgoing packets
    assert 0 == subprocess.call(['iptables', '-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT', '-w']) # Accept incoming packets for any outgoing flow
    assert 0 == subprocess.call(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', args.wan, '-j', 'SNAT', '--to-source', wan_ip, '--random-fully', '-w']) # Accept incoming connections that we have
    # In case of symmetric NAT, we are done now, the system will do its job.
    sys.exit(0)

# Process packets
def process_packet(data):
    pkt = ip.IP(data)

    if args.type == 'full':
        combo = (pkt.src, pkt.udp.sport)
    elif args.type == 'address':
        combo = (pkt.src, pkt.udp.sport, pkt.dst)
    elif args.type == 'port':
        combo = (pkt.src, pkt.udp.sport, pkt.dst, pkt.udp.dport)

    # If we already know this address/port combination, just refresh the timestamp
    if combo in mapping:
        t, natport = mapping[combo]
        mapping[combo] = (time.time(), natport)
        return 1

    # Add a new mapping
    natport = str(random.randint(32768, 65535))
    mapping[combo] = (time.time(), natport)

    if args.type == 'full':
        src = inet_ntoa(combo[0])
        sport = str(combo[1])
        if verbose:
            print "Adding mapping for", src, sport, ">", natport
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "PREROUTING", "-p", "udp", "-i", args.wan, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from anywhere to this NAT port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.wan, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
    elif args.type == 'address':
        src = inet_ntoa(combo[0])
        sport = str(combo[1])
        dst = inet_ntoa(combo[2])
        if verbose:
            print "Adding mapping for", src, sport, ">", natport, "to", dst
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-d", dst, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "PREROUTING", "-p", "udp", "-i", args.wan, "-s", dst, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from the destination address to this NAT port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.wan, "-s", dst, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from the destination address to the LAN source port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-d", dst, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
    elif args.type == 'port':
        src = inet_ntoa(combo[0])
        sport = str(combo[1])
        dst = inet_ntoa(combo[2])
        dport = str(combo[3])
        if verbose:
            print "Adding mapping for", src, sport, ">", natport, "to", dst, dport
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-d", dst, "--dport", dport, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        assert 0 == subprocess.call(["iptables", "-t", "nat", "-A" , "PREROUTING", "-p", "udp", "-i", args.wan, "-s", dst, "--sport", dport, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from the destination address+port to this NAT port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.wan, "-s", dst, "--sport", dport, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from the destination address+port to the LAN source port
        assert 0 == subprocess.call(["iptables", "-A" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-d", dst, "--dport", dport, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port

def process_timeout():
    now = time.time()
    expired = []

    for combo, tport in mapping.iteritems():
        t, natport = tport
        if now > t + args.timeout:
            expired.append(combo)

    for combo in expired:
        if args.type == 'full':
            src = inet_ntoa(combo[0])
            sport = str(combo[1])
            if verbose:
                print "Removing mapping for", src, sport, ">", natport
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.wan, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "PREROUTING", "-p", "udp", "-i", args.wan, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from anywhere to this NAT port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        elif args.type == 'address':
            src = inet_ntoa(combo[0])
            sport = str(combo[1])
            dst = inet_ntoa(combo[2])
            if verbose:
                print "Removing mapping for", src, sport, ">", natport, "to", dst
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-d", dst, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.wan, "-s", dst, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from the destination address to the LAN source port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "PREROUTING", "-p", "udp", "-i", args.wan, "-s", dst, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from the destination address to this NAT port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-d", dst, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        elif args.type == 'port':
            src = inet_ntoa(combo[0])
            sport = str(combo[1])
            dst = inet_ntoa(combo[2])
            dport = str(combo[3])
            if verbose:
                print "Removing mapping for", src, sport, ">", natport, "to", dst, dport
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.lan, "-s", src, "--sport", sport, "-o", args.wan, "-d", dst, "--dport", dport, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from anywhere to the LAN source port
            assert 0 == subprocess.call(["iptables", "-D" , "FORWARD", "-p", "udp", "-i", args.wan, "-s", dst, "--sport", dport, "--dport", sport, "-o", args.lan, "-j", "ACCEPT", "-w"]) # Incoming FORWARD rule: allow packets from the destination address+port to the LAN source port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "PREROUTING", "-p", "udp", "-i", args.wan, "-s", dst, "--sport", dport, "--dport", natport, "-j", "DNAT", "--to-destination", src + ":" + sport, "-w"]) # Incoming NAT rule: allow packets from the destination address+port to this NAT port
            assert 0 == subprocess.call(["iptables", "-t", "nat", "-D" , "POSTROUTING", "-p", "udp", "-o", args.wan, "-s", src, "--sport", sport, "-d", dst, "--dport", dport, "-j", "SNAT", "--to-source", wan_ip + ":" + natport, "-w"]) # Outoing NAT rule
        del(mapping[combo])
    if expired:
        subprocess.call(["conntrack", "-D", "-p", "udp"])

def main_loop():
    r, w = os.pipe()

    # Callback that processes the packets that are logged
    def cb(payload):
        data = payload.get_data()
        os.write(w, data)

    # Listen for packets being logged in a separate process
    childpid = os.fork()
    if not childpid:
        os.close(0)
        os.close(1)
        os.close(2)
        os.close(r)
        l = nflog.log()
        l.set_callback(cb)
        l.fast_open(0, AF_INET)
        l.try_run()
        l.unbind(AF_INET)
        l.close()
        w.close()
        sys.exit(1)

    os.close(w)

    if args.daemon:
        fds = [r]
    else:
        print "Running"
        fds = [0, r]

    # Wait for packets being sent to us
    while True:
        res = select.select(fds, [], [], 1)
        if 0 in res[0]:
            os.kill(childpid, 9)
            sys.exit(0)
        elif r in res[0]:
            try:
                process_packet(os.read(r, 4096))
            except:
                pass
        else:
            process_timeout()

if args.daemon:
    with daemon.DaemonContext():
        main_loop()
else:
    main_loop()
