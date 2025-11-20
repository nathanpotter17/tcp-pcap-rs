# TCP PCAP & STM

```
"Civilization advances by extending the number of important
operations which we can perform without thinking about them."

- Alfred North Whitehead
```

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

# Databases as Values - Rich Hickey

```
"Time is atomic, epochal succession of process events"
```

```
"There is a becoming of continuity, but no continuity of becoming"
```

People call filesystems, key:value stores, and etc 'databases', however, they are
quite the opposite. Databases are about leveraging data - if there is no leverage,
it simply is a 'data store'.

Firstly, State:
- Must be organized to support queries
- Sorted set of facts
    - Maintaining sorted sets has been proven to be wasted space and ptime
- Key idea is to accumulate change and novelty in memory, and periodically
merge that state onto disk. Use persistent trees.
- Collect, sort, flatten, diff, merge.

Secondly, Memory Index:
- Persistent sorted set
- Large internal nodes
- Pluggable comparators
- 2 sorts always maintained
    - EAVT, AEVT
        - plus AVET, VAET

Thirdly, Storage:
- Log of tx asserts/retracts (in tree)
- Various covering indexes (trees)
- Storage requirements
    - Data segment values (K -> V)
    - Atoms (consistent read)
    - Pods (conditional put)

Finally, Process:
- Assert/retract can't express transformation
- transaction function:
    - (f db & args) -> tx-data
- tx-data: assert|retract|(tx-fn args...)
- Expand/splice until all asserts/retracts

With this functional rep. we can represent any process transformation:
- Assert, Retract, or composite operation, which are all F(DB) + arguments -> tx-data

Additionally, Transactor is an independent process:
- Accepts transactions
    - expands, applies, logs, broadcasts (reader loop)
- Cannot be root based if using epochal time model for new state mapping
- Periodic indexing, background thread
- Indexing creates garbage
    - Storage GC

Additionally, Peers:
- Peers directly access storage service directly
- Have own query engine
- have live mem index and merging
- two-tier cache
    - segments (on/off heap)
    - Datoms w/ object values (on heap)

DB Simplicity
- Epochal state
    - coordination only for process
- Same query, same results: stable bases
- Tx's well defined
    - functional accretion

# STMs - Rich Hickey

Uniform State Transistion Model
- 'change-state' reference function [args*]
- function will be passed current state of the reference (plus any args)
- return value of function will be the next state of the reference
- snapshot of 'current' state always available with de-ref
- No user locking, and no deadlocks

This means we are afforded a 'Persistent Edit', where
- New value is function of the old
- shares immutable structure
- doesnt impede any readers
- Edit is not impeded by any readers

Next, our new version is just an Atomic State transistion.
- Always coordinated: Anytime someone dereferences this AFTER the atomic state transistion, readers will see the new value.
    - Multiple semantics
- Next dereference sees the new value
- Consumers of values are unaffected

As of Refs and Transactions
- Refs can only be changed within a transaction.
- All changes are Atomic and Isolated
    - All - or - None change model (atomicity)
    whereby every change to a ref made within a tx
    occurs or none do at all
    - No tx sees the effects of any other tx's while
    it is running
- Transactions are speculative (You May Not Win, Retry Limit, and thus, no side effects)

Gotchas
- Read tracking is a faulty was of trying to solve the problem of well synced STMs
- HashMaps DO NOT preserve ordering!

Implementation - STM
- Not a lock-free spinning optimistic design...
- Uses locks, wait/notify to avoid churn
- Deadlock detection + barging
- One timestamp CAS is only global resource
- No read tracking
- Course grained orientation
    - Refs + persistent data structures
- Readers don't impede writers/readers, writers

References to Immutable Values is Key!

Another STM: Agentic State
- Each agent manages independent state
- state changes through actions, which are ordinary functions (state=>new-state)
- actions are dispatched using send or send off which return immediately.
- actions occur **async** on thread-pool threads
- only one action per agent happens at a time, mailbox queue - serial processing.

Agents State
- Agent state always accessible, via deref/A,
but may not reflect all actions.
- Any dispatches made during an action are held until **after** the state
- Agents coordinate with tx's - any dispatches made during a transaction are held until
it commits
- Agents are not Actors (Erlang/Scala)

# Actor Governance

```rust
// main.rs - Enhanced DIAGON Actor-Based P2P System
// Replace entire main.rs content

use std::{
    thread,
    sync::{mpsc, Arc, Mutex, atomic::{AtomicBool, Ordering}},
    net::{TcpStream, TcpListener, SocketAddr},
    io::{Read, Write, ErrorKind},
    collections::{HashMap, HashSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use pcap::{Device, Capture};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// ============================================================================
// CORE TYPES (from DIAGON)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub cid: Cid,
    pub entry_type: EntryType,
    pub data: Vec<u8>,
    pub creator: Did,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntryType {
    Knowledge { category: String, concept: String, content: String },
    Proposal { text: String },
    Vote { target: Cid, support: bool },
    Prune { target: Cid, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Connect(Did, Vec<u8>, [u8; 32]),
    Challenge([u8; 32]),
    Response(Vec<u8>),
    Elaborate(String),
    Propose(Did, Entry, String),
    Vote(Did, Cid, bool, String, Vec<u8>),
    Heartbeat(Did),
    Shutdown,
}

// ============================================================================
// ACTOR MESSAGE TYPES WITH RESPONSE CHANNELS
// ============================================================================

pub enum SupervisorMsg {
    ActorFailed(ActorType, String),
    RestartActor(ActorType),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum ActorType {
    Network,
    Governance,
    Trust,
    Storage,
    Client(SocketAddr),
}

pub enum NetworkActorMsg {
    StartListening(SocketAddr, mpsc::Sender<Result<(), String>>),
    ConnectTo(SocketAddr, mpsc::Sender<Result<Did, String>>),
    SendTo(Did, Message),
    Broadcast(Message),
    ClientConnected(TcpStream, SocketAddr),
    ClientDisconnected(Did),
    GetPeers(mpsc::Sender<Vec<Did>>),
    Shutdown,
}

pub enum ClientActorMsg {
    Authenticate(Did, Vec<u8>, [u8; 32]),
    HandleMessage(Message),
    SendMessage(Message),
    GetState(mpsc::Sender<ClientState>),
    Disconnect,
}

#[derive(Debug, Clone)]
pub enum ClientState {
    Connected,
    Challenging([u8; 32]),
    Authenticated(Did),
    Disconnected,
}

pub enum GovernanceActorMsg {
    CreateProposal(Did, EntryType, String, mpsc::Sender<Result<Cid, String>>),
    CastVote(Did, Cid, bool, String, mpsc::Sender<Result<(), String>>),
    GetProposal(Cid, mpsc::Sender<Option<Proposal>>),
    CheckThresholds,
    Shutdown,
}

pub enum TrustActorMsg {
    UpdateTrust(Did, f64),
    GetTrust(Did, mpsc::Sender<f64>),
    DecayTrust,
    Shutdown,
}

pub enum StorageActorMsg {
    SaveEntry(Entry),
    GetEntry(Cid, mpsc::Sender<Option<Entry>>),
    SaveState(Vec<u8>),
    LoadState(mpsc::Sender<Option<Vec<u8>>>),
    Shutdown,
}

pub enum CaptureActorMsg {
    Start(String),
    Stop,
}

// ============================================================================
// ACTOR HANDLES (following Alice Ryhl pattern)
// ============================================================================

#[derive(Clone)]
pub struct SupervisorHandle {
    sender: mpsc::Sender<SupervisorMsg>,
}

impl SupervisorHandle {
    pub fn report_failure(&self, actor: ActorType, error: String) {
        let _ = self.sender.send(SupervisorMsg::ActorFailed(actor, error));
    }
    
    pub fn request_restart(&self, actor: ActorType) {
        let _ = self.sender.send(SupervisorMsg::RestartActor(actor));
    }
}

#[derive(Clone)]
pub struct NetworkActorHandle {
    sender: mpsc::Sender<NetworkActorMsg>,
}

impl NetworkActorHandle {
    pub fn start_listening(&self, addr: SocketAddr) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(NetworkActorMsg::StartListening(addr, tx))
            .map_err(|_| "Network actor dead".to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Timeout".to_string())?
    }
    
    pub fn connect_to(&self, addr: SocketAddr) -> Result<Did, String> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(NetworkActorMsg::ConnectTo(addr, tx))
            .map_err(|_| "Network actor dead".to_string())?;
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Timeout".to_string())?
    }
    
    pub fn broadcast(&self, msg: Message) {
        let _ = self.sender.send(NetworkActorMsg::Broadcast(msg));
    }
    
    pub fn get_peers(&self) -> Vec<Did> {
        let (tx, rx) = mpsc::channel();
        if self.sender.send(NetworkActorMsg::GetPeers(tx)).is_ok() {
            rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone)]
pub struct ClientActorHandle {
    sender: mpsc::Sender<ClientActorMsg>,
}

impl ClientActorHandle {
    pub fn send_message(&self, msg: Message) {
        let _ = self.sender.send(ClientActorMsg::SendMessage(msg));
    }
    
    pub fn get_state(&self) -> Option<ClientState> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(ClientActorMsg::GetState(tx)).ok()?;
        rx.recv_timeout(Duration::from_secs(1)).ok()
    }
    
    pub fn disconnect(&self) {
        let _ = self.sender.send(ClientActorMsg::Disconnect);
    }
}

#[derive(Clone)]
pub struct GovernanceActorHandle {
    sender: mpsc::Sender<GovernanceActorMsg>,
}

impl GovernanceActorHandle {
    pub fn create_proposal(&self, did: Did, entry: EntryType, elaboration: String) -> Result<Cid, String> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(GovernanceActorMsg::CreateProposal(did, entry, elaboration, tx))
            .map_err(|_| "Governance actor dead".to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Timeout".to_string())?
    }
    
    pub fn cast_vote(&self, did: Did, cid: Cid, support: bool, elaboration: String) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(GovernanceActorMsg::CastVote(did, cid, support, elaboration, tx))
            .map_err(|_| "Governance actor dead".to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Timeout".to_string())?
    }
}

#[derive(Clone)]
pub struct TrustActorHandle {
    sender: mpsc::Sender<TrustActorMsg>,
}

impl TrustActorHandle {
    pub fn update_trust(&self, did: Did, delta: f64) {
        let _ = self.sender.send(TrustActorMsg::UpdateTrust(did, delta));
    }
    
    pub fn get_trust(&self, did: Did) -> f64 {
        let (tx, rx) = mpsc::channel();
        if self.sender.send(TrustActorMsg::GetTrust(did, tx)).is_ok() {
            rx.recv_timeout(Duration::from_secs(1)).unwrap_or(0.5)
        } else {
            0.5
        }
    }
}

#[derive(Clone)]
pub struct StorageActorHandle {
    sender: mpsc::Sender<StorageActorMsg>,
}

impl StorageActorHandle {
    pub fn save_entry(&self, entry: Entry) {
        let _ = self.sender.send(StorageActorMsg::SaveEntry(entry));
    }
    
    pub fn get_entry(&self, cid: Cid) -> Option<Entry> {
        let (tx, rx) = mpsc::channel();
        self.sender.send(StorageActorMsg::GetEntry(cid, tx)).ok()?;
        rx.recv_timeout(Duration::from_secs(1)).ok().flatten()
    }
}

#[derive(Clone)]
pub struct CaptureActorHandle {
    sender: mpsc::Sender<CaptureActorMsg>,
}

impl CaptureActorHandle {
    pub fn start(&self, interface: String) {
        let _ = self.sender.send(CaptureActorMsg::Start(interface));
    }
    
    pub fn stop(&self) {
        let _ = self.sender.send(CaptureActorMsg::Stop);
    }
}

// ============================================================================
// SUPERVISOR ACTOR
// ============================================================================

struct SupervisorActor {
    receiver: mpsc::Receiver<SupervisorMsg>,
    network: Option<NetworkActorHandle>,
    governance: Option<GovernanceActorHandle>,
    trust: Option<TrustActorHandle>,
    storage: Option<StorageActorHandle>,
    running: Arc<AtomicBool>,
}

impl SupervisorActor {
    fn new(receiver: mpsc::Receiver<SupervisorMsg>, running: Arc<AtomicBool>) -> Self {
        Self {
            receiver,
            network: None,
            governance: None,
            trust: None,
            storage: None,
            running,
        }
    }
    
    fn run(mut self) {
        println!("[SUPERVISOR] Started");
        
        // Start child actors
        self.network = Some(Self::spawn_network_actor(self.running.clone()));
        self.governance = Some(Self::spawn_governance_actor(self.running.clone()));
        self.trust = Some(Self::spawn_trust_actor(self.running.clone()));
        self.storage = Some(Self::spawn_storage_actor(self.running.clone()));
        
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                SupervisorMsg::ActorFailed(actor_type, error) => {
                    println!("[SUPERVISOR] Actor failed: {:?} - {}", actor_type, error);
                    self.handle_actor_failure(actor_type);
                }
                SupervisorMsg::RestartActor(actor_type) => {
                    println!("[SUPERVISOR] Restarting actor: {:?}", actor_type);
                    self.restart_actor(actor_type);
                }
                SupervisorMsg::Shutdown => {
                    println!("[SUPERVISOR] Shutting down");
                    self.shutdown_all();
                    break;
                }
            }
        }
        
        println!("[SUPERVISOR] Exited");
    }
    
    fn handle_actor_failure(&mut self, actor_type: ActorType) {
        // Implement restart policy
        match actor_type {
            ActorType::Network => {
                println!("[SUPERVISOR] Critical failure: Network actor");
                self.shutdown_all();
            }
            ActorType::Governance | ActorType::Trust | ActorType::Storage => {
                self.restart_actor(actor_type);
            }
            ActorType::Client(_) => {
                // Client failures don't require restart
            }
        }
    }
    
    fn restart_actor(&mut self, actor_type: ActorType) {
        match actor_type {
            ActorType::Governance => {
                self.governance = Some(Self::spawn_governance_actor(self.running.clone()));
            }
            ActorType::Trust => {
                self.trust = Some(Self::spawn_trust_actor(self.running.clone()));
            }
            ActorType::Storage => {
                self.storage = Some(Self::spawn_storage_actor(self.running.clone()));
            }
            _ => {}
        }
    }
    
    fn shutdown_all(&self) {
        self.running.store(false, Ordering::Relaxed);
        // Actors will check running flag and exit
    }
    
    fn spawn_network_actor(running: Arc<AtomicBool>) -> NetworkActorHandle {
        let (tx, rx) = mpsc::channel();
        let actor = NetworkActor::new(rx, running);
        thread::spawn(move || actor.run());
        NetworkActorHandle { sender: tx }
    }
    
    fn spawn_governance_actor(running: Arc<AtomicBool>) -> GovernanceActorHandle {
        let (tx, rx) = mpsc::channel();
        let actor = GovernanceActor::new(rx, running);
        thread::spawn(move || actor.run());
        GovernanceActorHandle { sender: tx }
    }
    
    fn spawn_trust_actor(running: Arc<AtomicBool>) -> TrustActorHandle {
        let (tx, rx) = mpsc::channel();
        let actor = TrustActor::new(rx, running);
        thread::spawn(move || actor.run());
        TrustActorHandle { sender: tx }
    }
    
    fn spawn_storage_actor(running: Arc<AtomicBool>) -> StorageActorHandle {
        let (tx, rx) = mpsc::channel();
        let actor = StorageActor::new(rx, running);
        thread::spawn(move || actor.run());
        StorageActorHandle { sender: tx }
    }
}

// ============================================================================
// NETWORK ACTOR
// ============================================================================

struct NetworkActor {
    receiver: mpsc::Receiver<NetworkActorMsg>,
    listener: Option<TcpListener>,
    clients: HashMap<Did, ClientActorHandle>,
    running: Arc<AtomicBool>,
}

impl NetworkActor {
    fn new(receiver: mpsc::Receiver<NetworkActorMsg>, running: Arc<AtomicBool>) -> Self {
        Self {
            receiver,
            listener: None,
            clients: HashMap::new(),
            running,
        }
    }
    
    fn run(mut self) {
        println!("[NETWORK] Started");
        
        loop {
            // Check for shutdown
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            
            // Handle messages with timeout to allow checking running flag
            match self.receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(msg) => self.handle_message(msg),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check for incoming connections if listening
                    self.accept_connections();
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        
        // Cleanup
        for (_, client) in self.clients.drain() {
            client.disconnect();
        }
        
        println!("[NETWORK] Exited");
    }
    
    fn handle_message(&mut self, msg: NetworkActorMsg) {
        match msg {
            NetworkActorMsg::StartListening(addr, reply) => {
                let result = TcpListener::bind(addr)
                    .and_then(|l| {
                        l.set_nonblocking(true)?;
                        Ok(l)
                    })
                    .map(|l| {
                        self.listener = Some(l);
                        println!("[NETWORK] Listening on {}", addr);
                    })
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            NetworkActorMsg::ConnectTo(addr, reply) => {
                let result = self.connect_to_peer(addr);
                let _ = reply.send(result);
            }
            NetworkActorMsg::SendTo(did, msg) => {
                if let Some(client) = self.clients.get(&did) {
                    client.send_message(msg);
                }
            }
            NetworkActorMsg::Broadcast(msg) => {
                for client in self.clients.values() {
                    client.send_message(msg.clone());
                }
            }
            NetworkActorMsg::ClientConnected(stream, addr) => {
                self.handle_new_connection(stream, addr);
            }
            NetworkActorMsg::ClientDisconnected(did) => {
                self.clients.remove(&did);
                println!("[NETWORK] Client disconnected: {}", did.0);
            }
            NetworkActorMsg::GetPeers(reply) => {
                let peers: Vec<Did> = self.clients.keys().cloned().collect();
                let _ = reply.send(peers);
            }
            NetworkActorMsg::Shutdown => {
                self.running.store(false, Ordering::Relaxed);
            }
        }
    }
    
    fn accept_connections(&mut self) {
        if let Some(listener) = &self.listener {
            match listener.accept() {
                Ok((stream, addr)) => {
                    self.handle_new_connection(stream, addr);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // No connections ready
                }
                Err(e) => {
                    eprintln!("[NETWORK] Accept error: {}", e);
                }
            }
        }
    }
    
    fn handle_new_connection(&mut self, stream: TcpStream, addr: SocketAddr) {
        let (tx, rx) = mpsc::channel();
        let handle = ClientActorHandle { sender: tx };
        
        // Temporary DID until authenticated
        let temp_did = Did(format!("temp:{}", addr));
        self.clients.insert(temp_did.clone(), handle.clone());
        
        let actor = ClientActor::new(rx, stream, addr, self.running.clone());
        thread::spawn(move || actor.run());
        
        println!("[NETWORK] New connection from {}", addr);
    }
    
    fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<Did, String> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        
        let (tx, rx) = mpsc::channel();
        let handle = ClientActorHandle { sender: tx };
        
        let temp_did = Did(format!("temp:{}", addr));
        self.clients.insert(temp_did.clone(), handle);
        
        let actor = ClientActor::new(rx, stream, addr, self.running.clone());
        thread::spawn(move || actor.run());
        
        Ok(temp_did)
    }
}

// ============================================================================
// CLIENT ACTOR
// ============================================================================

struct ClientActor {
    receiver: mpsc::Receiver<ClientActorMsg>,
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: ClientState,
    buffer: Vec<u8>,
    running: Arc<AtomicBool>,
}

impl ClientActor {
    fn new(
        receiver: mpsc::Receiver<ClientActorMsg>,
        stream: TcpStream,
        peer_addr: SocketAddr,
        running: Arc<AtomicBool>,
    ) -> Self {
        let _ = stream.set_nonblocking(true);
        Self {
            receiver,
            stream,
            peer_addr,
            state: ClientState::Connected,
            buffer: vec![0; 65536],
            running,
        }
    }
    
    fn run(mut self) {
        println!("[CLIENT] Actor started for {}", self.peer_addr);
        
        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            
            // Check for actor messages
            match self.receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(msg) => {
                    if !self.handle_message(msg) {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            
            // Try to read from socket
            match self.stream.read(&mut self.buffer) {
                Ok(0) => {
                    println!("[CLIENT] Connection closed by {}", self.peer_addr);
                    break;
                }
                Ok(n) => {
                    self.process_data(&self.buffer[..n].to_vec());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[CLIENT] Read error from {}: {}", self.peer_addr, e);
                    break;
                }
            }
        }
        
        println!("[CLIENT] Actor exited for {}", self.peer_addr);
    }
    
    fn handle_message(&mut self, msg: ClientActorMsg) -> bool {
        match msg {
            ClientActorMsg::Authenticate(did, pubkey, pool) => {
                self.state = ClientState::Authenticated(did.clone());
                println!("[CLIENT] Authenticated as {}", did.0);
                true
            }
            ClientActorMsg::HandleMessage(msg) => {
                self.handle_protocol_message(msg);
                true
            }
            ClientActorMsg::SendMessage(msg) => {
                self.send_message(msg);
                true
            }
            ClientActorMsg::GetState(reply) => {
                let _ = reply.send(self.state.clone());
                true
            }
            ClientActorMsg::Disconnect => {
                println!("[CLIENT] Disconnecting {}", self.peer_addr);
                false
            }
        }
    }
    
    fn process_data(&mut self, data: &[u8]) {
        // Parse DIAGON message from data
        if data.len() >= 4 {
            let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if data.len() >= 4 + len {
                if let Ok(msg) = bincode::deserialize::<Message>(&data[4..4+len]) {
                    self.handle_protocol_message(msg);
                }
            }
        }
    }
    
    fn handle_protocol_message(&mut self, msg: Message) {
        println!("[CLIENT] Received {:?} from {}", 
                 std::mem::discriminant(&msg), self.peer_addr);
        
        match msg {
            Message::Connect(did, pubkey, pool) => {
                // Send challenge
                let mut challenge = [0u8; 32];
                self.state = ClientState::Challenging(challenge);
                self.send_message(Message::Challenge(challenge));
            }
            Message::Challenge(challenge) => {
                // Would sign challenge here
                self.send_message(Message::Response(vec![]));
            }
            Message::Response(signature) => {
                // Verify signature and authenticate
                if let ClientState::Challenging(_) = self.state {
                    // Would verify signature here
                    println!("[CLIENT] Authentication successful");
                }
            }
            Message::Elaborate(text) => {
                println!("[CLIENT] Elaboration: {}", text);
            }
            _ => {}
        }
    }
    
    fn send_message(&mut self, msg: Message) {
        if let Ok(data) = bincode::serialize(&msg) {
            let len = (data.len() as u32).to_be_bytes();
            let _ = self.stream.write_all(&len);
            let _ = self.stream.write_all(&data);
            let _ = self.stream.flush();
        }
    }
}

// ============================================================================
// GOVERNANCE ACTOR
// ============================================================================

#[derive(Clone)]
struct Proposal {
    cid: Cid,
    entry_type: EntryType,
    proposer: Did,
    elaboration: String,
    votes_for: HashSet<Did>,
    votes_against: HashSet<Did>,
    executed: bool,
}

struct GovernanceActor {
    receiver: mpsc::Receiver<GovernanceActorMsg>,
    proposals: HashMap<Cid, Proposal>,
    running: Arc<AtomicBool>,
}

impl GovernanceActor {
    fn new(receiver: mpsc::Receiver<GovernanceActorMsg>, running: Arc<AtomicBool>) -> Self {
        Self {
            receiver,
            proposals: HashMap::new(),
            running,
        }
    }
    
    fn run(mut self) {
        println!("[GOVERNANCE] Started");
        
        while let Ok(msg) = self.receiver.recv() {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            
            match msg {
                GovernanceActorMsg::CreateProposal(did, entry_type, elaboration, reply) => {
                    let cid = self.create_proposal(did, entry_type, elaboration);
                    let _ = reply.send(Ok(cid));
                }
                GovernanceActorMsg::CastVote(did, cid, support, elaboration, reply) => {
                    let result = self.cast_vote(did, cid, support, elaboration);
                    let _ = reply.send(result);
                }
                GovernanceActorMsg::GetProposal(cid, reply) => {
                    let _ = reply.send(self.proposals.get(&cid).cloned());
                }
                GovernanceActorMsg::CheckThresholds => {
                    self.check_execution_thresholds();
                }
                GovernanceActorMsg::Shutdown => break,
            }
        }
        
        println!("[GOVERNANCE] Exited");
    }
    
    fn create_proposal(&mut self, did: Did, entry_type: EntryType, elaboration: String) -> Cid {
        let mut hasher = Sha256::new();
        hasher.update(elaboration.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let cid = Cid(hash);
        
        self.proposals.insert(cid, Proposal {
            cid,
            entry_type,
            proposer: did,
            elaboration,
            votes_for: HashSet::new(),
            votes_against: HashSet::new(),
            executed: false,
        });
        
        println!("[GOVERNANCE] Created proposal {}", cid.short());
        cid
    }
    
    fn cast_vote(&mut self, did: Did, cid: Cid, support: bool, _elaboration: String) -> Result<(), String> {
        let proposal = self.proposals.get_mut(&cid)
            .ok_or("Proposal not found")?;
        
        if support {
            proposal.votes_for.insert(did);
        } else {
            proposal.votes_against.insert(did);
        }
        
        println!("[GOVERNANCE] Vote cast on {}: {}", cid.short(), support);
        Ok(())
    }
    
    fn check_execution_thresholds(&mut self) {
        for proposal in self.proposals.values_mut() {
            if !proposal.executed && proposal.votes_for.len() >= 2 {
                proposal.executed = true;
                println!("[GOVERNANCE] Executed proposal {}", proposal.cid.short());
            }
        }
    }
}

// ============================================================================
// TRUST ACTOR
// ============================================================================

struct TrustActor {
    receiver: mpsc::Receiver<TrustActorMsg>,
    scores: HashMap<Did, f64>,
    running: Arc<AtomicBool>,
}

impl TrustActor {
    fn new(receiver: mpsc::Receiver<TrustActorMsg>, running: Arc<AtomicBool>) -> Self {
        Self {
            receiver,
            scores: HashMap::new(),
            running,
        }
    }
    
    fn run(mut self) {
        println!("[TRUST] Started");
        
        while let Ok(msg) = self.receiver.recv() {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            
            match msg {
                TrustActorMsg::UpdateTrust(did, delta) => {
                    let score = self.scores.entry(did.clone()).or_insert(0.5);
                    *score = (*score + delta).max(0.0).min(1.0);
                    println!("[TRUST] Updated {} to {:.2}", did.0, score);
                }
                TrustActorMsg::GetTrust(did, reply) => {
                    let score = self.scores.get(&did).copied().unwrap_or(0.5);
                    let _ = reply.send(score);
                }
                TrustActorMsg::DecayTrust => {
                    for score in self.scores.values_mut() {
                        *score *= 0.95;
                    }
                    println!("[TRUST] Applied decay");
                }
                TrustActorMsg::Shutdown => break,
            }
        }
        
        println!("[TRUST] Exited");
    }
}

// ============================================================================
// STORAGE ACTOR
// ============================================================================

struct StorageActor {
    receiver: mpsc::Receiver<StorageActorMsg>,
    entries: HashMap<Cid, Entry>,
    running: Arc<AtomicBool>,
}

impl StorageActor {
    fn new(receiver: mpsc::Receiver<StorageActorMsg>, running: Arc<AtomicBool>) -> Self {
        Self {
            receiver,
            entries: HashMap::new(),
            running,
        }
    }
    
    fn run(mut self) {
        println!("[STORAGE] Started");
        
        while let Ok(msg) = self.receiver.recv() {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            
            match msg {
                StorageActorMsg::SaveEntry(entry) => {
                    println!("[STORAGE] Saved entry {}", entry.cid.short());
                    self.entries.insert(entry.cid, entry);
                }
                StorageActorMsg::GetEntry(cid, reply) => {
                    let _ = reply.send(self.entries.get(&cid).cloned());
                }
                StorageActorMsg::SaveState(data) => {
                    println!("[STORAGE] Saved state ({} bytes)", data.len());
                }
                StorageActorMsg::LoadState(reply) => {
                    let _ = reply.send(None); // Would load from disk
                }
                StorageActorMsg::Shutdown => break,
            }
        }
        
        println!("[STORAGE] Exited");
    }
}

// ============================================================================
// PACKET CAPTURE ACTOR
// ============================================================================

struct CaptureActor {
    receiver: mpsc::Receiver<CaptureActorMsg>,
}

impl CaptureActor {
    fn run(mut self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                CaptureActorMsg::Start(interface) => {
                    self.capture_packets(&interface);
                }
                CaptureActorMsg::Stop => break,
            }
        }
    }
    
    fn capture_packets(&mut self, interface: &str) {
        let devices = match Device::list() {
            Ok(devs) => devs,
            Err(e) => {
                eprintln!("[CAPTURE] Failed to list devices: {}", e);
                return;
            }
        };
        
        let device = devices.iter()
            .find(|d| d.name == interface || 
                      d.desc.as_ref().map(|s| s.contains(interface)).unwrap_or(false))
            .cloned()
            .unwrap_or_else(|| devices[0].clone());
        
        println!("[CAPTURE] Using device: {}", device.name);
        
        let mut cap = match Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[CAPTURE] Failed to open: {}", e);
                return;
            }
        };
        
        let _ = cap.filter("tcp port 9090", true);
        
        loop {
            match self.receiver.try_recv() {
                Ok(CaptureActorMsg::Stop) => break,
                _ => {}
            }
            
            match cap.next_packet() {
                Ok(packet) => self.parse_packet(&packet.data),
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    eprintln!("[CAPTURE] Error: {}", e);
                    break;
                }
            }
        }
    }
    
    fn parse_packet(&self, packet: &[u8]) {
        if packet.len() < 54 { return; }
        
        // Parse headers (simplified)
        let ip_offset = 14; // Ethernet header
        let ip_header_len = ((packet[ip_offset] & 0x0F) * 4) as usize;
        let tcp_offset = ip_offset + ip_header_len;
        
        if packet.len() < tcp_offset + 20 { return; }
        
        let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
        
        let tcp_header_len = ((packet[tcp_offset + 12] >> 4) * 4) as usize;
        let payload_offset = tcp_offset + tcp_header_len;
        
        if payload_offset < packet.len() {
            let payload = &packet[payload_offset..];
            
            // Try to parse DIAGON message
            if payload.len() >= 4 {
                let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                if payload.len() >= 4 + len {
                    if let Ok(msg) = bincode::deserialize::<Message>(&payload[4..4+len]) {
                        println!("[CAPTURE] DIAGON {:?} on {}->{}",
                                 std::mem::discriminant(&msg), src_port, dst_port);
                    }
                }
            }
        }
    }
}

// ============================================================================
// NODE API
// ============================================================================

pub struct Node {
    supervisor: SupervisorHandle,
    network: NetworkActorHandle,
    governance: GovernanceActorHandle,
    trust: TrustActorHandle,
    storage: StorageActorHandle,
    capture: Option<CaptureActorHandle>,
    running: Arc<AtomicBool>,
}

impl Node {
    pub fn new() -> Arc<Self> {
        let running = Arc::new(AtomicBool::new(true));
        
        // Create supervisor
        let (sup_tx, sup_rx) = mpsc::channel();
        let supervisor = SupervisorHandle { sender: sup_tx };
        
        // Create actor handles (supervisor will spawn them)
        let (net_tx, net_rx) = mpsc::channel();
        let (gov_tx, gov_rx) = mpsc::channel();
        let (trust_tx, trust_rx) = mpsc::channel();
        let (stor_tx, stor_rx) = mpsc::channel();
        
        let network = NetworkActorHandle { sender: net_tx };
        let governance = GovernanceActorHandle { sender: gov_tx };
        let trust = TrustActorHandle { sender: trust_tx };
        let storage = StorageActorHandle { sender: stor_tx };
        
        // Start supervisor
        let sup_running = running.clone();
        thread::spawn(move || {
            let supervisor = SupervisorActor::new(sup_rx, sup_running);
            supervisor.run();
        });
        
        // Start actors
        let net_running = running.clone();
        thread::spawn(move || {
            let actor = NetworkActor::new(net_rx, net_running);
            actor.run();
        });
        
        let gov_running = running.clone();
        thread::spawn(move || {
            let actor = GovernanceActor::new(gov_rx, gov_running);
            actor.run();
        });
        
        let trust_running = running.clone();
        thread::spawn(move || {
            let actor = TrustActor::new(trust_rx, trust_running);
            actor.run();
        });
        
        let stor_running = running.clone();
        thread::spawn(move || {
            let actor = StorageActor::new(stor_rx, stor_running);
            actor.run();
        });
        
        // Optional packet capture
        let capture = if std::env::var("ENABLE_PCAP").is_ok() {
            let (cap_tx, cap_rx) = mpsc::channel();
            thread::spawn(move || {
                let actor = CaptureActor { receiver: cap_rx };
                actor.run();
            });
            Some(CaptureActorHandle { sender: cap_tx })
        } else {
            None
        };
        
        Arc::new(Self {
            supervisor,
            network,
            governance,
            trust,
            storage,
            capture,
            running,
        })
    }
    
    pub fn listen(&self, addr: &str) -> Result<(), String> {
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|_| "Invalid address")?;
        self.network.start_listening(socket_addr)
    }
    
    pub fn connect(&self, addr: &str) -> Result<Did, String> {
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|_| "Invalid address")?;
        self.network.connect_to(socket_addr)
    }
    
    pub fn elaborate(&self, text: &str) {
        self.network.broadcast(Message::Elaborate(text.to_string()));
    }
    
    pub fn propose(&self, did: Did, entry_type: EntryType, elaboration: String) -> Result<Cid, String> {
        self.governance.create_proposal(did, entry_type, elaboration)
    }
    
    pub fn vote(&self, did: Did, cid: Cid, support: bool, elaboration: String) -> Result<(), String> {
        self.governance.cast_vote(did, cid, support, elaboration)
    }
    
    pub fn get_trust(&self, did: Did) -> f64 {
        self.trust.get_trust(did)
    }
    
    pub fn get_peers(&self) -> Vec<Did> {
        self.network.get_peers()
    }
    
    pub fn enable_capture(&self, interface: &str) {
        if let Some(capture) = &self.capture {
            capture.start(interface.to_string());
        }
    }
    
    pub fn shutdown(&self) {
        println!("[NODE] Initiating shutdown");
        self.running.store(false, Ordering::Relaxed);
        self.supervisor.sender.send(SupervisorMsg::Shutdown).ok();
        thread::sleep(Duration::from_secs(1));
        println!("[NODE] Shutdown complete");
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn main() {
    println!("DIAGON - Actor-Based P2P Governance System");
    println!("=========================================\n");
    
    let node = Node::new();
    
    // Start listening
    if let Err(e) = node.listen("0.0.0.0:9090") {
        eprintln!("Failed to start listening: {}", e);
        return;
    }
    
    // Enable packet capture if requested
    if std::env::var("ENABLE_PCAP").is_ok() {
        let interface = std::env::var("PCAP_INTERFACE")
            .unwrap_or_else(|_| "lo".to_string());
        node.enable_capture(&interface);
    }
    
    // Run until interrupted
    println!("Node running. Press Ctrl+C to shutdown.\n");
    
    // Simple command loop for testing
    loop {
        thread::sleep(Duration::from_secs(10));
        
        // Check if we should shutdown
        if !node.running.load(Ordering::Relaxed) {
            break;
        }
        
        // Example: broadcast elaboration
        node.elaborate("Periodic trust building elaboration");
        
        // Show peer count
        let peers = node.get_peers();
        println!("Connected peers: {}", peers.len());
    }
    
    node.shutdown();
}
```