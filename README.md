# net-events

## Description

net-events is a simple packet-sniffer application which creates CloudEvents per packet.
It's intended use is to report all network activity in a k8 pod.

## TODO
- [x] Sniff packets
- [x] Create CloudEvents with data per packet
- [ ] Publish to PubSub
- [ ] Allow filtering by IP / CIDR / Protocol
- [ ] Allow enable/disable IPv4 / IPv6
- [ ] Create example with Minikube
