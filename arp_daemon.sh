#!/bin/bash
while true; do
  /usr/sbin/arp -a > /tmp/netmaster_arp.txt 2>/dev/null
  sleep 3
done
