# The Actor Model

```rust
// The actor recipe by Alice Ryhl
struct MyActor {
    receiver: mpsc::Receiver<ActorMessage>,
    connection: TcpStream,
}

impl MyActor {
    async fn handle_message() -> io::Result<()> {
        match msg {
            ActorMessage::SendMessage { message, respond_to } => {
                self.connection.write_all(message.as_bytes()).await?;
                let response = self.connection.read_u32().await?;
                let _ = respond_to.send(response);
                Ok(())
            }
        }
    }
}

async fn run_my_actor(mut Actor: MyActor) {
    while let Some(msg) = actor.receiver.recv.await {
        actor.handle_message(msg).await.unwrap();
    }
}

enum ActorMessage {
    SendMessage {
        message: String,
        respond_to: oneshot::Sender<u32>,
    }
}

#[derive(Clone)]
pub struct MyActorHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl MyActorHandle {
    pub fn new(conn: TcpStream) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = MyActor::new(receiver, conn);
        tokio::spawn(run_my_actor(actor));

        Self { sender }
    }

    pub async fn send_message(&self, msg: String) -> u32 {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SendMessage {
            respond_to: send,
            message: msg,
        };

        // Ignore send failurs. If the send fails, so does the recv.await
        // below. No need to check fail twice.
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed");
    }
}
```

```rust
// Cargo.toml additions needed:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// pcap = "2"
// thiserror = "1"
// tracing = "0.1"
// tracing-subscriber = "0.3"

use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex},
    time::{timeout, Duration},
};
use pcap::{Device, Capture};
use thiserror::Error;
use tracing::{error, info, warn, debug};

// Error types
#[derive(Error, Debug)]
enum ActorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Timeout")]
    Timeout,
}

// Message types for actors
#[derive(Debug)]
enum ServerMessage {
    NewConnection(TcpStream, std::net::SocketAddr),
    Shutdown(oneshot::Sender<()>),
    GetStats(oneshot::Sender<ServerStats>),
}

#[derive(Debug)]
enum ClientMessage {
    Data(Vec<u8>),
    Close,
}

#[derive(Debug, Clone)]
struct PacketInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: String,
    payload: Vec<u8>,
    timestamp: std::time::Instant,
}

#[derive(Debug)]
enum PacketCaptureMessage {
    StartCapture(String), // device name
    StopCapture,
    GetPackets(oneshot::Sender<Vec<PacketInfo>>),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Debug, Clone)]
struct ServerStats {
    total_connections: usize,
    active_connections: usize,
    bytes_received: usize,
    bytes_sent: usize,
}

// Client Actor - handles single TCP connection
struct ClientActor {
    id: uuid::Uuid,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    receiver: mpsc::Receiver<ClientMessage>,
    stats_tx: mpsc::Sender<ClientStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
struct ClientStats {
    id: uuid::Uuid,
    bytes_in: usize,
    bytes_out: usize,
    disconnected: bool,
}

impl ClientActor {
    fn new(
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        receiver: mpsc::Receiver<ClientMessage>,
        stats_tx: mpsc::Sender<ClientStats>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            stream,
            peer_addr,
            receiver,
            stats_tx,
            shutdown_tx: None,
        }
    }

    async fn run(mut self) {
        info!("Client actor {} started for {}", self.id, self.peer_addr);
        let mut buffer = vec![0u8; 4096];
        let mut bytes_in = 0;
        let mut bytes_out = 0;

        loop {
            tokio::select! {
                // Handle incoming data from client
                result = self.stream.read(&mut buffer) => {
                    match result {
                        Ok(0) => {
                            info!("Client {} disconnected (EOF)", self.peer_addr);
                            break;
                        }
                        Ok(n) => {
                            bytes_in += n;
                            debug!("Received {} bytes from {}", n, self.peer_addr);
                            
                            // Echo back
                            if let Err(e) = self.stream.write_all(&buffer[..n]).await {
                                error!("Failed to write to client {}: {}", self.peer_addr, e);
                                break;
                            }
                            bytes_out += n;
                        }
                        Err(e) => {
                            error!("Read error from {}: {}", self.peer_addr, e);
                            break;
                        }
                    }
                }
                
                // Handle control messages
                Some(msg) = self.receiver.recv() => {
                    match msg {
                        ClientMessage::Data(data) => {
                            if let Err(e) = self.stream.write_all(&data).await {
                                error!("Failed to send data to client: {}", e);
                                break;
                            }
                            bytes_out += data.len();
                        }
                        ClientMessage::Close => {
                            info!("Closing connection to {}", self.peer_addr);
                            break;
                        }
                    }
                }
            }
        }

        // Send final stats
        let _ = self.stats_tx.send(ClientStats {
            id: self.id,
            bytes_in,
            bytes_out,
            disconnected: true,
        }).await;

        // Notify shutdown complete if requested
        if let Some(tx) = self.shutdown_tx {
            let _ = tx.send(());
        }
    }
}

// Client Actor Handle
#[derive(Clone)]
struct ClientHandle {
    id: uuid::Uuid,
    sender: mpsc::Sender<ClientMessage>,
}

impl ClientHandle {
    fn spawn(
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        stats_tx: mpsc::Sender<ClientStats>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let actor = ClientActor::new(stream, peer_addr, rx, stats_tx);
        let id = actor.id;
        
        tokio::spawn(actor.run());
        
        Self { id, sender: tx }
    }

    async fn send_data(&self, data: Vec<u8>) -> Result<(), ActorError> {
        self.sender.send(ClientMessage::Data(data))
            .await
            .map_err(|_| ActorError::ChannelClosed)
    }

    async fn close(&self) -> Result<(), ActorError> {
        self.sender.send(ClientMessage::Close)
            .await
            .map_err(|_| ActorError::ChannelClosed)
    }
}

// Server Actor - manages all client connections
struct ServerActor {
    receiver: mpsc::Receiver<ServerMessage>,
    clients: Arc<Mutex<Vec<ClientHandle>>>,
    stats: Arc<Mutex<ServerStats>>,
    stats_rx: mpsc::Receiver<ClientStats>,
}

impl ServerActor {
    fn new(
        receiver: mpsc::Receiver<ServerMessage>,
        stats_rx: mpsc::Receiver<ClientStats>,
    ) -> Self {
        Self {
            receiver,
            clients: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ServerStats {
                total_connections: 0,
                active_connections: 0,
                bytes_received: 0,
                bytes_sent: 0,
            })),
            stats_rx,
        }
    }

    async fn run(mut self) {
        info!("Server actor started");
        
        loop {
            tokio::select! {
                // Handle server messages
                Some(msg) = self.receiver.recv() => {
                    match msg {
                        ServerMessage::NewConnection(stream, addr) => {
                            let stats_tx = self.stats_rx.sender.clone();
                            let handle = ClientHandle::spawn(stream, addr, stats_tx);
                            
                            let mut clients = self.clients.lock().await;
                            clients.push(handle);
                            
                            let mut stats = self.stats.lock().await;
                            stats.total_connections += 1;
                            stats.active_connections = clients.len();
                            
                            info!("New client connected. Active: {}", clients.len());
                        }
                        ServerMessage::Shutdown(respond_to) => {
                            info!("Server shutdown requested");
                            
                            // Close all client connections
                            let clients = self.clients.lock().await;
                            for client in clients.iter() {
                                let _ = client.close().await;
                            }
                            
                            let _ = respond_to.send(());
                            break;
                        }
                        ServerMessage::GetStats(respond_to) => {
                            let stats = self.stats.lock().await;
                            let _ = respond_to.send(stats.clone());
                        }
                    }
                }
                
                // Handle client statistics updates
                Some(client_stats) = self.stats_rx.recv() => {
                    let mut stats = self.stats.lock().await;
                    stats.bytes_received += client_stats.bytes_in;
                    stats.bytes_sent += client_stats.bytes_out;
                    
                    if client_stats.disconnected {
                        let mut clients = self.clients.lock().await;
                        clients.retain(|c| c.id != client_stats.id);
                        stats.active_connections = clients.len();
                        info!("Client disconnected. Active: {}", clients.len());
                    }
                }
            }
        }
        
        info!("Server actor stopped");
    }
}

// Server Handle
#[derive(Clone)]
struct ServerHandle {
    sender: mpsc::Sender<ServerMessage>,
}

impl ServerHandle {
    fn spawn() -> (Self, mpsc::Sender<ClientStats>) {
        let (tx, rx) = mpsc::channel(32);
        let (stats_tx, stats_rx) = mpsc::channel(32);
        
        let actor = ServerActor::new(rx, stats_rx);
        tokio::spawn(actor.run());
        
        (Self { sender: tx }, stats_tx)
    }

    async fn new_connection(&self, stream: TcpStream, addr: std::net::SocketAddr) -> Result<(), ActorError> {
        self.sender.send(ServerMessage::NewConnection(stream, addr))
            .await
            .map_err(|_| ActorError::ChannelClosed)
    }

    async fn get_stats(&self) -> Result<ServerStats, ActorError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(ServerMessage::GetStats(tx))
            .await
            .map_err(|_| ActorError::ChannelClosed)?;
        rx.await.map_err(|_| ActorError::ChannelClosed)
    }

    async fn shutdown(&self) -> Result<(), ActorError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(ServerMessage::Shutdown(tx))
            .await
            .map_err(|_| ActorError::ChannelClosed)?;
        rx.await.map_err(|_| ActorError::ChannelClosed)
    }
}

// Packet Capture Actor
struct PacketCaptureActor {
    receiver: mpsc::Receiver<PacketCaptureMessage>,
    packets: Vec<PacketInfo>,
    capture_handle: Option<tokio::task::JoinHandle<()>>,
    packet_tx: mpsc::Sender<PacketInfo>,
    packet_rx: mpsc::Receiver<PacketInfo>,
}

impl PacketCaptureActor {
    fn new(receiver: mpsc::Receiver<PacketCaptureMessage>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            receiver,
            packets: Vec::new(),
            capture_handle: None,
            packet_tx: tx,
            packet_rx: rx,
        }
    }

    async fn run(mut self) {
        info!("Packet capture actor started");
        
        loop {
            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                    match msg {
                        PacketCaptureMessage::StartCapture(device_name) => {
                            if self.capture_handle.is_some() {
                                warn!("Capture already running");
                                continue;
                            }
                            
                            let tx = self.packet_tx.clone();
                            self.capture_handle = Some(tokio::spawn(async move {
                                if let Err(e) = Self::capture_loop(device_name, tx).await {
                                    error!("Capture error: {}", e);
                                }
                            }));
                            
                            info!("Started packet capture");
                        }
                        PacketCaptureMessage::StopCapture => {
                            if let Some(handle) = self.capture_handle.take() {
                                handle.abort();
                                info!("Stopped packet capture");
                            }
                        }
                        PacketCaptureMessage::GetPackets(respond_to) => {
                            let _ = respond_to.send(self.packets.clone());
                        }
                        PacketCaptureMessage::Shutdown(respond_to) => {
                            if let Some(handle) = self.capture_handle.take() {
                                handle.abort();
                            }
                            let _ = respond_to.send(());
                            break;
                        }
                    }
                }
                
                Some(packet) = self.packet_rx.recv() => {
                    // Keep last 1000 packets in memory
                    if self.packets.len() >= 1000 {
                        self.packets.remove(0);
                    }
                    
                    info!("Captured packet: {}:{} -> {}:{} [{}]",
                          packet.src_ip, packet.src_port,
                          packet.dst_ip, packet.dst_port,
                          packet.flags);
                    
                    self.packets.push(packet);
                }
            }
        }
        
        info!("Packet capture actor stopped");
    }

    async fn capture_loop(device_name: String, tx: mpsc::Sender<PacketInfo>) -> Result<(), ActorError> {
        // Run blocking pcap in dedicated thread
        let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel(100);
        
        std::thread::spawn(move || {
            let devices = Device::list().expect("Failed to list devices");
            let device = devices.iter()
                .find(|d| d.name == device_name)
                .cloned()
                .expect("Device not found");
            
            let mut cap = Capture::from_device(device)
                .expect("Failed to open device")
                .promisc(true)
                .snaplen(65535)
                .timeout(1000)
                .open()
                .expect("Failed to activate capture");
            
            cap.filter("tcp port 9090", true).expect("Failed to set filter");
            
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(info) = parse_packet_data(&packet.data) {
                            let _ = sync_tx.blocking_send(info);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        eprintln!("Capture error: {:?}", e);
                        break;
                    }
                }
            }
        });
        
        // Forward packets from sync thread to async actor
        while let Some(packet) = sync_rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
        
        Ok(())
    }
}

// Parse packet helper function
fn parse_packet_data(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 4 { return None; }
    
    let mut offset = 4; // Windows loopback header
    
    // IP header
    if packet.len() < offset + 20 { return None; }
    let ip_header_len = ((packet[offset] & 0x0F) * 4) as usize;
    
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
    
    let payload = if offset >= packet.len() { 
        Vec::new() 
    } else { 
        packet[offset..].to_vec()
    };
    
    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload,
        timestamp: std::time::Instant::now(),
    })
}

// Packet Capture Handle
#[derive(Clone)]
struct PacketCaptureHandle {
    sender: mpsc::Sender<PacketCaptureMessage>,
}

impl PacketCaptureHandle {
    fn spawn() -> Self {
        let (tx, rx) = mpsc::channel(32);
        let actor = PacketCaptureActor::new(rx);
        tokio::spawn(actor.run());
        Self { sender: tx }
    }

    async fn start_capture(&self, device: String) -> Result<(), ActorError> {
        self.sender.send(PacketCaptureMessage::StartCapture(device))
            .await
            .map_err(|_| ActorError::ChannelClosed)
    }

    async fn stop_capture(&self) -> Result<(), ActorError> {
        self.sender.send(PacketCaptureMessage::StopCapture)
            .await
            .map_err(|_| ActorError::ChannelClosed)
    }

    async fn get_packets(&self) -> Result<Vec<PacketInfo>, ActorError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(PacketCaptureMessage::GetPackets(tx))
            .await
            .map_err(|_| ActorError::ChannelClosed)?;
        rx.await.map_err(|_| ActorError::ChannelClosed)
    }

    async fn shutdown(&self) -> Result<(), ActorError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(PacketCaptureMessage::Shutdown(tx))
            .await
            .map_err(|_| ActorError::ChannelClosed)?;
        rx.await.map_err(|_| ActorError::ChannelClosed)
    }
}

// Supervisor actor to coordinate everything
struct SupervisorActor {
    server_handle: ServerHandle,
    capture_handle: PacketCaptureHandle,
    shutdown_rx: oneshot::Receiver<()>,
}

impl SupervisorActor {
    fn new(
        server_handle: ServerHandle,
        capture_handle: PacketCaptureHandle,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            server_handle,
            capture_handle,
            shutdown_rx,
        }
    }

    async fn run(mut self) {
        info!("Supervisor started");
        
        // Start packet capture
        let device = if std::env::var("TEST_MODE").is_ok() {
            find_loopback_device()
        } else {
            find_network_device()
        }.expect("No suitable network device found");
        
        if let Err(e) = self.capture_handle.start_capture(device).await {
            error!("Failed to start capture: {}", e);
        }
        
        // Monitor system health
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            tokio::select! {
                _ = &mut self.shutdown_rx => {
                    info!("Supervisor shutdown signal received");
                    break;
                }
                
                _ = stats_interval.tick() => {
                    // Periodic health check
                    match self.server_handle.get_stats().await {
                        Ok(stats) => {
                            info!("Server stats - Active: {}, Total: {}, In: {} bytes, Out: {} bytes",
                                  stats.active_connections,
                                  stats.total_connections,
                                  stats.bytes_received,
                                  stats.bytes_sent);
                        }
                        Err(e) => {
                            error!("Failed to get server stats: {}", e);
                        }
                    }
                    
                    match self.capture_handle.get_packets().await {
                        Ok(packets) => {
                            info!("Captured {} packets", packets.len());
                        }
                        Err(e) => {
                            error!("Failed to get packets: {}", e);
                        }
                    }
                }
            }
        }
        
        // Graceful shutdown
        info!("Initiating graceful shutdown");
        
        let _ = self.capture_handle.stop_capture().await;
        let _ = self.server_handle.shutdown().await;
        let _ = self.capture_handle.shutdown().await;
        
        info!("Supervisor stopped");
    }
}

fn find_loopback_device() -> Option<String> {
    Device::list().ok()?.into_iter()
        .find(|d| d.desc.as_ref()
            .map(|s| s.to_lowercase().contains("loopback"))
            .unwrap_or(false))
        .map(|d| d.name)
}

fn find_network_device() -> Option<String> {
    Device::list().ok()?.into_iter()
        .find(|d| {
            let desc = d.desc.as_ref()
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            desc.contains("wi-fi") || desc.contains("ethernet")
        })
        .map(|d| d.name)
}

// Main application
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9090".to_string());
    
    // Create actors
    let (server_handle, _stats_tx) = ServerHandle::spawn();
    let capture_handle = PacketCaptureHandle::spawn();
    
    // Create supervisor
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let supervisor = SupervisorActor::new(
        server_handle.clone(),
        capture_handle.clone(),
        shutdown_rx,
    );
    
    // Start supervisor
    let supervisor_task = tokio::spawn(supervisor.run());
    
    // Start TCP listener
    let listener = TcpListener::bind(&addr).await?;
    info!("Server listening on {}", addr);
    
    // Handle shutdown signals
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Shutdown signal received (Ctrl+C)");
        let _ = shutdown_tx_clone.send(());
    });
    
    // Accept connections with timeout
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        if let Err(e) = server_handle.new_connection(stream, addr).await {
                            error!("Failed to handle new connection: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            
            // Check if supervisor died
            _ = &mut supervisor_task => {
                info!("Supervisor terminated, shutting down");
                break;
            }
        }
    }
    
    Ok(())
}

// Add uuid to Cargo.toml:
// uuid = { version = "1", features = ["v4"] }
```

```rust
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use std::io;

// Actor message types - simple enum with oneshot responders
enum EchoMessage {
    Read {
        respond_to: oneshot::Sender<io::Result<Vec<u8>>>,
    },
    Write {
        data: Vec<u8>,
        respond_to: oneshot::Sender<io::Result<usize>>,
    },
    Close {
        respond_to: oneshot::Sender<()>,
    },
}

// The actor - owns the TcpStream connection
struct EchoActor {
    receiver: mpsc::Receiver<EchoMessage>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
}

impl EchoActor {
    fn new(
        receiver: mpsc::Receiver<EchoMessage>,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            receiver,
            stream,
            peer_addr,
        }
    }

    // Handle individual messages
    async fn handle_message(&mut self, msg: EchoMessage) -> io::Result<()> {
        match msg {
            EchoMessage::Read { respond_to } => {
                let mut buf = vec![0u8; 1024];
                match self.stream.read(&mut buf).await {
                    Ok(n) => {
                        buf.truncate(n);
                        let _ = respond_to.send(Ok(buf));
                    }
                    Err(e) => {
                        let _ = respond_to.send(Err(e));
                    }
                }
            }
            EchoMessage::Write { data, respond_to } => {
                let result = self.stream.write_all(&data).await
                    .map(|_| data.len());
                let _ = respond_to.send(result);
            }
            EchoMessage::Close { respond_to } => {
                let _ = self.stream.shutdown().await;
                let _ = respond_to.send(());
                return Err(io::Error::new(io::ErrorKind::Other, "Connection closed"));
            }
        }
        Ok(())
    }
}

// Actor run loop
async fn run_echo_actor(mut actor: EchoActor) {
    println!("Actor started for {}", actor.peer_addr);
    
    while let Some(msg) = actor.receiver.recv().await {
        if actor.handle_message(msg).await.is_err() {
            break;
        }
    }
    
    println!("Actor stopped for {}", actor.peer_addr);
}

// Handle for interacting with the actor
#[derive(Clone)]
pub struct EchoHandle {
    sender: mpsc::Sender<EchoMessage>,
    peer_addr: std::net::SocketAddr,
}

impl EchoHandle {
    pub fn new(stream: TcpStream, peer_addr: std::net::SocketAddr) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = EchoActor::new(receiver, stream, peer_addr);
        
        tokio::spawn(run_echo_actor(actor));
        
        Self { sender, peer_addr }
    }

    pub async fn read(&self) -> io::Result<Vec<u8>> {
        let (send, recv) = oneshot::channel();
        let msg = EchoMessage::Read { respond_to: send };
        
        // Ignore send errors. If send fails, recv.await will also fail
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or_else(|_| {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "Actor died"))
        })
    }

    pub async fn write(&self, data: Vec<u8>) -> io::Result<usize> {
        let (send, recv) = oneshot::channel();
        let msg = EchoMessage::Write { data, respond_to: send };
        
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or_else(|_| {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "Actor died"))
        })
    }

    pub async fn close(&self) {
        let (send, recv) = oneshot::channel();
        let msg = EchoMessage::Close { respond_to: send };
        
        let _ = self.sender.send(msg).await;
        let _ = recv.await;
    }
}

// Simple echo service using the actor
async fn handle_connection(handle: EchoHandle) {
    loop {
        match handle.read().await {
            Ok(data) if data.is_empty() => {
                println!("EOF from {}", handle.peer_addr);
                break;
            }
            Ok(data) => {
                println!("Received {} bytes from {}", data.len(), handle.peer_addr);
                
                // Echo back
                if let Err(e) = handle.write(data).await {
                    eprintln!("Write error: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }
    
    handle.close().await;
}

// Optional: Simple packet parser if you want to keep pcap functionality
#[cfg(feature = "pcap")]
mod packet_capture {
    use pcap::{Device, Capture};
    use tokio::sync::mpsc;
    
    pub struct PacketInfo {
        pub src: String,
        pub dst: String,
        pub data: Vec<u8>,
    }
    
    pub async fn capture_packets(tx: mpsc::Sender<PacketInfo>) {
        // Spawn blocking thread for pcap
        tokio::task::spawn_blocking(move || {
            let device = Device::lookup()
                .expect("Failed to find device")
                .expect("No device found");
            
            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .open()
                .unwrap();
            
            cap.filter("tcp port 9090", true).unwrap();
            
            loop {
                if let Ok(packet) = cap.next_packet() {
                    // Minimal parsing - just extract IPs
                    if packet.len() > 30 {
                        let info = PacketInfo {
                            src: format!("{}.{}.{}.{}", 
                                packet[12], packet[13], packet[14], packet[15]),
                            dst: format!("{}.{}.{}.{}", 
                                packet[16], packet[17], packet[18], packet[19]),
                            data: packet.data.to_vec(),
                        };
                        let _ = tx.blocking_send(info);
                    }
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    
    let listener = TcpListener::bind(&addr).await?;
    println!("Server listening on {}", addr);
    
    // Optional: Start packet capture
    #[cfg(feature = "pcap")]
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(packet_capture::capture_packets(tx));
        
        // Print captured packets
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                println!("Packet: {} -> {} ({} bytes)", 
                    packet.src, packet.dst, packet.data.len());
            }
        });
    }
    
    // Main accept loop
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {}", addr);
        
        // Create actor handle for this connection
        let handle = EchoHandle::new(stream, addr);
        
        // Spawn task to handle this connection
        tokio::spawn(handle_connection(handle));
    }
}
```