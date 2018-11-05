/*
    netwoek_sim.c -- Container Management API
    Copyright (C) 2017  Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "network_sim.h"

char *choose_arch;

/*Takes bridgeName as input parameter and creates a bridge */
int create_bridge(const char* bridgeName) {
  char command[100] = "brctl addbr ";
  strcat(command, bridgeName);
  int create_bridge_status = system(command);
  assert(create_bridge_status == 0);
  fprintf(stderr, "%s bridge created\n", bridgeName);
  return 0;
}

/* Add interface for the bridge created */
void add_interface(const char* bridgeName, const char* interfaceName) {
  char command[100] = "brctl addif ";
  char cmd[100] = "dhclient ";

  strcat(command, bridgeName);
  strcat(command, " ");
  strcat(command, interfaceName);
  int addif_status = system(command);
  assert(addif_status == 0);
  strcat(cmd, bridgeName);
  int dhclient_status = system(cmd);
  assert(dhclient_status == 0);
  fprintf(stderr, "Added interface for %s\n", bridgeName);
  return;
}

/* Create a veth pair and bring them up */
void add_veth_pair(const char* vethName1, const char* vethName2) {
  char command[100] = "ip link add ";
  char upCommand1[100] = "ip link set ";
  char upCommand2[100] = "ip link set ";

  strcat(command, vethName1);
  strcat(command, " type veth peer name ");
  strcat(command, vethName2);
  int link_add_status = system(command);
  assert(link_add_status == 0);
  strcat(upCommand1, vethName1);
  strcat(upCommand1, " up");
  int link_set_veth1_status = system(upCommand1);
  assert(link_set_veth1_status == 0);
  strcat(upCommand2, vethName2);
  strcat(upCommand2, " up");
  int link_set_veth2_status = system(upCommand2);
  assert(link_set_veth2_status == 0);
  fprintf(stderr, "Added veth pairs %s and %s\n", vethName1, vethName2);
  return;
}

/* Bring the interface up for the bridge created */
void bring_if_up(const char* bridgeName) {
  char command[300] = "ifconfig ";
  char dhcommand[300] = "dhclient ";
  strcat(command, bridgeName);
  strcat(command, " up");
  int if_up_status = system(command);
  assert(if_up_status == 0);
  sleep(2);
  fprintf(stderr, "Interface brought up for %s created\n", bridgeName);
  return;
}

/**
 * Replace all occurrences of a given a word in string.
 */
void replaceAll(char *str, const char *oldWord, const char *newWord) {
  char *pos, temp[BUFSIZ];
  int index = 0;
  int owlen;
  owlen = strlen(oldWord);
  while((pos = strstr(str, oldWord)) != NULL) {
    strcpy(temp, str);
    index = pos - str;
    str[index] = '\0';
    strcat(str, newWord);
    strcat(str, temp + index + owlen);
  }
}

/* Switches the bridge for a given container */
void switch_bridge(const char *containerName, const char * currentBridge, const char *newBridge) {
  char command[100] = "lxc-stop -n ";
  char command_start[100] = "lxc-start -n ";
  fprintf(stderr, "Switching %s container to %s\n", containerName, newBridge);
  strcat(command, containerName);
  strcat(command_start, containerName);
  int container_stop_status = system(command);
  assert(container_stop_status == 0);
  sleep(2);
  FILE * fPtr;
  FILE * fTemp;
  char path[300] = "/var/lib/lxc/";
  strcat(path,containerName);
  strcat(path,"/config");

  char buffer[BUFSIZ];
  /*  Open all required files */
  fPtr  = fopen(path, "r");
  fTemp = fopen("replace.tmp", "w");
  if(fPtr == NULL || fTemp == NULL) {
    fprintf(stderr, "\nUnable to open file.\n");
    fprintf(stderr, "Please check whether file exists and you have read/write privilege.\n");
    exit(EXIT_SUCCESS);
  }

  while((fgets(buffer, BUFSIZ, fPtr)) != NULL) {
    replaceAll(buffer, currentBridge, newBridge);
    fputs(buffer, fTemp);
  }
  fclose(fPtr);
  fclose(fTemp);
  remove(path);
  rename("replace.tmp", path);
  fprintf(stderr, "Switching procedure done successfully\n");
  int container_start_status = system(command_start);
  assert(container_start_status == 0);
  sleep(2);
}

/* Bring the interface down for the bridge created */
void bring_if_down(const char* bridgeName) {
  char command[300] = "ip link set dev ";
  strcat(command, bridgeName);
  strcat(command, " down");
  int if_down_status = system(command);
  assert(if_down_status == 0);
  fprintf(stderr, "Interface brought down for %s created\n", bridgeName);
  return;
}

/* Delete interface for the bridge created */
void del_interface(const char* bridgeName, const char* interfaceName) {
  char command[300] = "brctl delif ";
  strcat(command, bridgeName);
  strcat(command, interfaceName);
  int if_delete_status = system(command);
  assert(if_delete_status == 0);
  fprintf(stderr, "Deleted interface for %s\n", bridgeName);
  return;
}

/*Takes bridgeName as input parameter and deletes a bridge */
int delete_bridge(const char* bridgeName) {
  bring_if_down(bridgeName);
  char command[300] = "brctl delbr ";
  strcat(command, bridgeName);
  int bridge_delete = system(command);
  assert(bridge_delete == 0);
  fprintf(stderr, "%s bridge deleted\n", bridgeName);
  sleep(2);
  return 0;
}

/*Creates container on a specified bridge with added interface*/
int create_container_on_bridge(const char* containerName, const char* bridgeName, const char* ifName) {
  char command[100] = "lxc-create -t download -n ";
  char cmd[100] = " -- -d ubuntu -r trusty -a ";
  char start[100] = "lxc-start -n ";
  FILE * fPtr;
  char path[300] = "/var/lib/lxc/";
  strcat(path,containerName);
  strcat(path,"/config");
  strcat(command, containerName);
  strcat(command, cmd);
  strcat(command, choose_arch);
  int container_create_status = system(command);
  assert(container_create_status == 0);
  sleep(3);
  assert(fPtr = fopen(path, "a+"));
  fprintf(fPtr, "lxc.net.0.name = eth0\n");
  fprintf(fPtr, "\n");
  fprintf(fPtr, "lxc.net.1.type = veth\n");
  fprintf(fPtr, "lxc.net.1.flags = up\n");
  fprintf(fPtr, "lxc.net.1.link = %s\n", bridgeName);
  fprintf(fPtr, "lxc.net.1.name = %s\n", ifName);
  fprintf(fPtr, "lxc.net.1.hwaddr = 00:16:3e:ab:xx:xx\n");
  fclose(fPtr);
  strcat(start, containerName);
  int container_start_status = system(start);
  assert(container_start_status == 0);
  sleep(3);
  fprintf(stderr, "Created %s on %s with interface name %s\n", containerName, bridgeName, ifName);
  return 0;
}

/*Configures dnsmasq and iptables for the specified container with inputs of listen address and dhcp range*/
void config_dnsmasq(const char* containerName, const char* ifName, const char* listenAddress, const char* dhcpRange) {
  char command[500] = "echo \"apt-get install dnsmasq iptables -y\" | lxc-attach -n ";
  strcat(command, containerName);
  strcat(command, " --");
  int iptables_install_status = system(command);
  assert(iptables_install_status == 0);
  sleep(5);
  char com1[300] = "echo \"echo \"interface=eth1\" >> /etc/dnsmasq.conf\" | lxc-attach -n ";
  strcat(com1, containerName);
  strcat(com1, " --");
  int dnsmasq_status = system(com1);
  assert(dnsmasq_status == 0);
  sleep(5);
  char com2[300] = "echo \"echo \"bind-interfaces\" >> /etc/dnsmasq.conf\" | lxc-attach -n ";
  strcat(com2, containerName);
  strcat(com2, " --");
  dnsmasq_status = system(com2);
  assert(dnsmasq_status == 0);
  sleep(5);
  char com3[300] = "echo \"echo \"listen-address=";
  strcat(com3, listenAddress);
  strcat(com3, "\" >> /etc/dnsmasq.conf\" | lxc-attach -n ");
  strcat(com3, containerName);
  strcat(com3, " --");
  dnsmasq_status = system(com3);
  assert(dnsmasq_status == 0);
  sleep(5);
  char com4[300] = "echo \"echo \"dhcp-range=";
  strcat(com4, dhcpRange);
  strcat(com4, "\" >> /etc/dnsmasq.conf\" | lxc-attach -n ");
  strcat(com4, containerName);
  strcat(com4, " --");
  dnsmasq_status = system(com4);
  assert(dnsmasq_status == 0);
  sleep(5);
  char cmd[300] = "echo \"ifconfig ";
  strcat(cmd, ifName);
  strcat(cmd, " ");
  strcat(cmd, listenAddress);
  strcat(cmd, " netmask 255.255.255.0 up\" | lxc-attach -n ");
  strcat(cmd, containerName);
  strcat(cmd, " --");
  dnsmasq_status = system(cmd);
  assert(dnsmasq_status == 0);
  sleep(2	);
  char com[500] = "echo \"service dnsmasq restart >> /dev/null\" | lxc-attach -n ";
  strcat(com, containerName);
  strcat(com, " --");
  dnsmasq_status = system(com);
  assert(dnsmasq_status == 0);
  sleep(2);
  fprintf(stderr, "Configured dnsmasq in %s with interface name %s, listen-address = %s, dhcp-range = %s\n", containerName, ifName, listenAddress, dhcpRange);
  return;
}

/*configure the NAT rules inside the container*/
void config_nat(const char* containerName, const char* listenAddress) {
  char* last_dot_in_ip;
  int last_ip_byte = 0;
  char new_ip[300];
  strncpy(new_ip, listenAddress, sizeof(new_ip));
  assert(last_dot_in_ip = strrchr(new_ip, '.'));
  assert(snprintf(last_dot_in_ip + 1, 4, "%d", last_ip_byte) >= 0);
  char comd[300] = "echo \"iptables -t nat -A POSTROUTING -s ";
  strcat(comd, new_ip);
  strcat(comd, "/24 ! -d ");
  strcat(comd, new_ip);
  strcat(comd, "/24 -j MASQUERADE\" | lxc-attach -n ");
  strcat(comd, containerName);
  strcat(comd, " --");
  int conf_nat_status = system(comd);
  assert(conf_nat_status == 0);
  sleep(2);
  fprintf(stderr, "Configured NAT on %s\n", containerName);
  return;
}

/*Creates a NAT layer on a specified bridge with certain dhcp range to allocate ips for nodes*/
int create_nat_layer(const char* containerName, const char* bridgeName, const char* ifName, const char* listenAddress, char* dhcpRange) {
  create_bridge(bridgeName);
  bring_if_up(bridgeName);
  create_container_on_bridge(containerName, bridgeName, ifName);
  config_dnsmasq(containerName, ifName, listenAddress, dhcpRange);
  config_nat(containerName, listenAddress);
  fprintf(stderr, "NAT layer created with %s\n", containerName);
  return 0;
}

/*Destroys the NAT layer created*/
void destroy_nat_layer(const char* containerName, const char* bridgeName) {
  bring_if_down(bridgeName);
  delete_bridge(bridgeName);
  char command[100] = "lxc-stop -n ";
  strcat(command, containerName);
  int container_stop_status = system(command);
  assert(container_stop_status == 0);
  char destroy[100] = "lxc-destroy -n ";
  strcat(destroy, containerName);
  strcat(destroy, " -s");
  int container_destroy_status = system(destroy);
  assert(container_destroy_status == 0);
  fprintf(stderr, "NAT layer destroyed with %s\n", containerName);
  return;
}

/*Add incoming firewall rules for ipv4 addresses with packet type and port number*/
void incoming_firewall_ipv4(const char* packetType, int portNumber) {
  char buf[5];
  snprintf(buf, sizeof(buf), "%d", portNumber);
  assert(system("iptables -F") == 0);
  assert(system("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") == 0);
  assert(system("iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT") == 0);
  char command[100] = "iptables -A INPUT -p ";
  strcat(command, packetType);
  strcat(command, " --dport ");
  strcat(command, buf);
  strcat(command, " -j ACCEPT");
  assert(system(command) == 0);
  sleep(2);
  assert(system("iptables -A INPUT -j DROP") == 0);
  fprintf(stderr, "Firewall for incoming requests added on IPv4");
  assert(system("iptables -L") == 0);
  return;
}

/*Add incoming firewall rules for ipv6 addresses with packet type and port number*/
void incoming_firewall_ipv6(const char* packetType, int portNumber) {
  char buf[5];
  snprintf(buf, sizeof(buf), "%d", portNumber);
  assert(system("ip6tables -F") == 0);
  assert(system("ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") == 0);
  assert(system("ip6tables -A INPUT -s ::1 -d ::1 -j ACCEPT") == 0);
  char command[100] = "ip6tables -A INPUT -p ";
  strcat(command, packetType);
  strcat(command, " --dport ");
  strcat(command, buf);
  strcat(command, " -j ACCEPT");
  assert(system(command) == 0);
  sleep(2);
  assert(system("ip6tables -A INPUT -j DROP") == 0);
  fprintf(stderr, "Firewall for incoming requests added on IPv6");
  assert(system("ip6tables -L") == 0);
  return;
}

/*Add outgoing firewall rules for ipv4 addresses with packet type and port number*/
void outgoing_firewall_ipv4(const char* packetType, int portNumber) {
  char buf[5];
  snprintf(buf, sizeof(buf), "%d", portNumber);
  assert(system("iptables -F") == 0);
  assert(system("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") == 0);
  assert(system("iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT") == 0);
  char command[100] = "iptables -A OUTPUT -p ";
  strcat(command, packetType);
  strcat(command, " --dport ");
  strcat(command, buf);
  strcat(command, " -j ACCEPT");
  assert(system(command) == 0);
  sleep(2);
  assert(system("iptables -A OUTPUT -j DROP") == 0);
  fprintf(stderr, "Firewall for outgoing requests added on IPv4");
  assert(system("iptables -L") == 0);
  return;
}

/*Add outgoing firewall rules for ipv6 addresses with packet type and port number*/
void outgoing_firewall_ipv6(const char* packetType, int portNumber) {
  char buf[5];
  snprintf(buf, sizeof(buf), "%d", portNumber);
  assert(system("ip6tables -F") == 0);
  assert(system("ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") == 0);
  assert(system("ip6tables -A OUTPUT -s ::1 -d ::1 -j ACCEPT") == 0);
  char command[100] = "ip6tables -A OUTPUT -p ";
  strcat(command, packetType);
  strcat(command, " --dport ");
  strcat(command, buf);
  strcat(command, " -j ACCEPT");
  assert(system(command) == 0);
  sleep(2);
  assert(system("ip6tables -A OUTPUT -j DROP") == 0);
  fprintf(stderr, "Firewall for outgoing requests added on IPv6");
  assert(system("ip6tables -L") == 0);
  return;
}
