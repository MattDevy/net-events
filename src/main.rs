use chrono::{TimeZone, Utc};
use cloudevents::{EventBuilder, EventBuilderV10};
use etherparse::{InternetSlice::*, ReadError, SlicedPacket, TransportSlice::*};
use pcap::{Capture, Packet};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
enum IpProtocolKind {
    UNKNOWN,
    UDP,
    TCP,
}

#[derive(Serialize, Deserialize)]
enum IpAddrKind {
    UNKNOWN,
    V4,
    V6,
}

#[derive(Serialize, Deserialize)]
struct PacketEventData {
    source_ip: IpAddr,
    dest_ip: IpAddr,
    version: IpAddrKind,
    length: u64,
    source_port: u16,
    dest_port: u16,
    protocol: IpProtocolKind,
}

impl<'a> TryFrom<Packet<'a>> for PacketEventData {
    type Error = ReadError;

    fn try_from(packet: Packet) -> Result<Self, Self::Error> {
        let mut packet_data = PacketEventData::default();
        packet_data.length = packet.header.len as u64;

        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => return Err(value),
            Ok(value) => {
                match value.ip {
                    Some(Ipv4(value)) => {
                        packet_data.source_ip = IpAddr::V4(value.source_addr());
                        packet_data.dest_ip = IpAddr::V4(value.destination_addr());
                        packet_data.version = IpAddrKind::V4;
                    }
                    Some(Ipv6(value, _)) => {
                        packet_data.source_ip = IpAddr::V6(value.source_addr());
                        packet_data.dest_ip = IpAddr::V6(value.destination_addr());
                        packet_data.version = IpAddrKind::V6;
                    }
                    None => {}
                }

                match value.transport {
                    Some(Udp(value)) => {
                        packet_data.protocol = IpProtocolKind::UDP;
                        packet_data.source_port = value.source_port();
                        packet_data.dest_port = value.destination_port();
                    }
                    Some(Tcp(value)) => {
                        packet_data.protocol = IpProtocolKind::TCP;
                        packet_data.source_port = value.source_port();
                        packet_data.dest_port = value.destination_port();
                    }
                    None => {}
                }
            }
        }
        Ok(packet_data)
    }
}

impl Default for PacketEventData {
    fn default() -> PacketEventData {
        PacketEventData {
            source_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dest_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            version: IpAddrKind::UNKNOWN,
            length: 0,
            source_port: 0,
            dest_port: 0,
            protocol: IpProtocolKind::UNKNOWN,
        }
    }
}

fn main() {
    let mut cap = Capture::from_device("wlo1")
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        let dt = Utc.timestamp(packet.header.ts.tv_sec, packet.header.ts.tv_usec as u32);
        let packet_data = PacketEventData::try_from(packet).unwrap();
        let event = EventBuilderV10::new()
            .id(&Uuid::new_v4().to_hyphenated().to_string())
            .ty("net-events.packet")
            .source("com.github.mattdevy.net-events")
            .time(dt)
            .data(
                "application/json",
                serde_json::to_string(&packet_data).unwrap(),
            )
            .build()
            .unwrap();

        println!("{}", event.to_string());
    }
}
