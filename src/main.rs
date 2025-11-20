use std::{
    thread,
    sync::{mpsc, Arc, Mutex},
    net::{TcpStream, TcpListener},
    io::{Read, Write, ErrorKind},
};
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

// Client Actor
struct ClientActor {
    receiver: mpsc::Receiver<ClientMessage>,
    stream: TcpStream,
    peer_addr: String,
}

enum ClientMessage {
    ProcessData(Vec<u8>),
    Shutdown,
}

impl ClientActor {
    fn run(mut self) {
        let mut buffer = [0; 1024];
        
        // Set non-blocking mode for stream to allow checking messages
        self.stream.set_nonblocking(true).expect("Failed to set non-blocking");
        
        loop {
            // Check for messages
            if let Ok(msg) = self.receiver.try_recv() {
                match msg {
                    ClientMessage::ProcessData(data) => {
                        println!("Processing {} bytes: {:02x?}", data.len(), &data);
                        if let Err(e) = self.stream.write_all(&data) {
                            eprintln!("Write error: {:?}", e);
                            break;
                        }
                    }
                    ClientMessage::Shutdown => {
                        println!("Shutting down client {}", self.peer_addr);
                        break;
                    }
                }
            }
            
            // Try to read from socket
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("Client closed: {}", self.peer_addr);
                    break;
                }
                Ok(n) => {
                    let data = buffer[0..n].to_vec();
                    println!("Received {} bytes", n);
                    
                    // Echo back immediately
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("Write error: {:?}", e);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // No data available, sleep briefly
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("Read error: {:?}", e);
                    break;
                }
            }
        }
        
        println!("Connection finished: {}", self.peer_addr);
    }
}

#[derive(Clone)]
struct ClientHandle {
    sender: mpsc::Sender<ClientMessage>,
}

impl ClientHandle {
    fn new(stream: TcpStream) -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let peer_addr = stream.peer_addr()
            .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
        
        println!("New client actor for: {}", peer_addr);
        
        let actor = ClientActor {
            receiver,
            stream,
            peer_addr,
        };
        
        thread::spawn(move || actor.run());
        
        Self { sender }
    }
    
    fn send_data(&self, data: Vec<u8>) -> Result<(), mpsc::SendError<ClientMessage>> {
        self.sender.send(ClientMessage::ProcessData(data))
    }
    
    fn shutdown(&self) -> Result<(), mpsc::SendError<ClientMessage>> {
        self.sender.send(ClientMessage::Shutdown)
    }
}

// Packet Capture Actor
struct PacketCaptureActor {
    receiver: mpsc::Receiver<CaptureMessage>,
}

enum CaptureMessage {
    Start,
    Stop,
}

impl PacketCaptureActor {
    fn run(self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                CaptureMessage::Start => {
                    println!("Starting packet capture");
                    self.capture_packets();
                }
                CaptureMessage::Stop => {
                    println!("Stopping packet capture");
                    break;
                }
            }
        }
    }
    
    fn capture_packets(&self) {
        // Your existing capture logic
        let devices = Device::list().expect("Failed to list devices");
        let use_loopback = std::env::var("TEST_MODE").is_ok();
        
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
                    
                    if let Some((tcp_info, payload)) = Self::parse_packet(&packet.data) {
                        println!("{}:{} -> {}:{}", 
                                 tcp_info.src_ip, tcp_info.src_port,
                                 tcp_info.dst_ip, tcp_info.dst_port);
                        println!("Flags: {}", tcp_info.flags);
                        
                        if !payload.is_empty() {
                            println!("Payload: {} bytes", payload.len());
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
}

#[derive(Clone)]
struct CaptureHandle {
    sender: mpsc::Sender<CaptureMessage>,
}

impl CaptureHandle {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let actor = PacketCaptureActor { receiver };
        
        thread::spawn(move || actor.run());
        
        Self { sender }
    }
    
    fn start(&self) -> Result<(), mpsc::SendError<CaptureMessage>> {
        self.sender.send(CaptureMessage::Start)
    }
}

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9090".to_string());
    
    // Start capture actor
    let capture_handle = CaptureHandle::new();
    capture_handle.start().expect("Failed to start capture");
    
    // Server actor could be added here too
    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    println!("Server listening on {}", addr);
    
    // Store client handles if you need to manage them
    let clients = Arc::new(Mutex::new(Vec::<ClientHandle>::new()));
    
    for stream_result in listener.incoming() {
        if let Ok(stream) = stream_result {
            let handle = ClientHandle::new(stream);
            clients.lock().unwrap().push(handle);
        }
    }
}