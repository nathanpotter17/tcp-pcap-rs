use std::{env, thread, io::{Read, Write, ErrorKind}, net::{TcpStream, TcpListener}};
use pcap::{Device, Capture};

struct TcpInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: String,
}

fn handle_client(mut stream: TcpStream) {
    let peer_addr = stream.peer_addr()
        .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
    
    println!("Handling connection from: {}", peer_addr);
    let mut buffer = [0; 1024];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Client Closed. EOF for {}", peer_addr);
                break;
            }
            Ok(n) => {
                println!("Application received {} bytes: {:02x?}", n, &buffer[0..n]);
                if let Err(e) = stream.write_all(&buffer[0..n]) {
                    eprintln!("Write error to client {}: {:?}", peer_addr, e);
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                if e.kind() == ErrorKind::ConnectionReset {
                    println!("Client {} reset connection", peer_addr);
                } else {
                    eprintln!("Read error from client {}: {:?}", peer_addr, e);
                }
                break;
            }
        }
    }
    println!("Connection finished for: {}", peer_addr);
}

fn capture_packets() {
    let devices = Device::list().expect("Failed to list devices");
    let use_loopback = env::var("TEST_MODE").is_ok();
    
    let device = if use_loopback {
        devices.iter().find(|d| 
            d.desc.as_ref()
                .map(|s| s.to_lowercase().contains("loopback"))
                .unwrap_or(false)
        ).expect("Loopback not found")
    } else {
        devices.iter().find(|d| {
            let desc = d.desc.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
            desc.contains("wi-fi") || desc.contains("ethernet")
        }).expect("Network adapter not found")
    }.clone();
    
    println!("Capturing on: {} ({})", device.name, 
             device.desc.as_ref().unwrap_or(&"N/A".to_string()));
    
    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true).snaplen(65535).timeout(1000)
        .open().expect("Failed to activate capture");
    
    cap.filter("tcp port 9090", true).expect("Failed to set filter");
    
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("═══════════════════════════════════════");
                println!("Packet: {} bytes", packet.len());
                
                if let Some((tcp_info, payload)) = parse_packet(&packet.data) {
                    println!("{}:{} -> {}:{}", 
                             tcp_info.src_ip, tcp_info.src_port,
                             tcp_info.dst_ip, tcp_info.dst_port);
                    println!("Flags: {}", tcp_info.flags);
                    println!("Seq: {}, Ack: {}", tcp_info.seq, tcp_info.ack);
                    
                    if !payload.is_empty() {
                        println!("Payload: {} bytes: {:02x?}", payload.len(), payload);
                        if let Ok(text) = std::str::from_utf8(payload) {
                            println!("Text: {:?}", text);
                        }
                    }
                }
                println!("═══════════════════════════════════════\n");
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => eprintln!("Error capturing: {:?}", e),
        }
    }
}

fn parse_packet(packet: &[u8]) -> Option<(TcpInfo, &[u8])> {
    if packet.len() < 4 { return None; }
    
    let mut offset = 4; // Windows loopback header
    
    // IP header
    if packet.len() < offset + 20 { return None; }
    let ip_header_len = ((packet[offset] & 0x0F) * 4) as usize;
    
    // Extract IP addresses
    let src_ip = format!("{}.{}.{}.{}", 
        packet[offset + 12], packet[offset + 13], 
        packet[offset + 14], packet[offset + 15]);
    let dst_ip = format!("{}.{}.{}.{}", 
        packet[offset + 16], packet[offset + 17], 
        packet[offset + 18], packet[offset + 19]);
    
    offset += ip_header_len;
    
    // TCP header
    if packet.len() < offset + 20 { return None; }
    
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let seq = u32::from_be_bytes([
        packet[offset + 4], packet[offset + 5], 
        packet[offset + 6], packet[offset + 7]
    ]);
    let ack = u32::from_be_bytes([
        packet[offset + 8], packet[offset + 9], 
        packet[offset + 10], packet[offset + 11]
    ]);
    
    let tcp_flags = packet[offset + 13];
    let mut flags = String::new();
    if tcp_flags & 0x02 != 0 { flags.push_str("SYN "); }
    if tcp_flags & 0x10 != 0 { flags.push_str("ACK "); }
    if tcp_flags & 0x01 != 0 { flags.push_str("FIN "); }
    if tcp_flags & 0x04 != 0 { flags.push_str("RST "); }
    if tcp_flags & 0x08 != 0 { flags.push_str("PSH "); }
    
    let tcp_header_len = ((packet[offset + 12] >> 4) * 4) as usize;
    offset += tcp_header_len;
    
    let payload = if offset >= packet.len() { &[] } else { &packet[offset..] };
    
    Some((TcpInfo { src_ip, dst_ip, src_port, dst_port, seq, ack, flags }, payload))
}

fn main() {
    let addr = env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9090".to_string());
    
    thread::spawn(|| capture_packets());
    
    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    println!("Server listening on {}", addr);

    for stream_result in listener.incoming() {
        if let Ok(stream) = stream_result {
            thread::spawn(move || handle_client(stream));
        }
    }
}