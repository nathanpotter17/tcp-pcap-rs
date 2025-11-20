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

# Authentication Actor

```rust
// authenticated_server.rs - Adds DIAGON authentication to existing TCP server
// This wraps your existing implementation with authentication layer

use std::{
    thread,
    sync::{mpsc::{self, Sender, Receiver}, Arc, Mutex},
    net::{TcpStream, TcpListener},
    io::{self, Read, Write, ErrorKind, BufWriter},
    time::{SystemTime, UNIX_EPOCH, Duration, Instant},
    fs::{File, create_dir_all},
    path::Path,
    collections::HashMap,
};

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::RngCore;

// Include your existing server code
include!("your_existing_server.rs");

// ============================================================================
// CORE IDENTITY TYPES (from DIAGON)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn from_pubkey(pk: &PublicKey) -> Self {
        Did(format!("did:diagon:{}", hex::encode(&pk.as_bytes()[..32])))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    fn new(data: &[u8], node_did: &Did, nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(node_did.0.as_bytes());
        Cid(hasher.finalize().into())
    }
    
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

// ============================================================================
// PROTOCOL MESSAGES (from DIAGON, simplified)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMessage {
    Connect(Did, Vec<u8>, [u8; 32]),  // DID, pubkey, pool_commitment
    Challenge([u8; 32]),                // 32-byte nonce
    Response(Vec<u8>),                  // signature of challenge
    Elaborate(String),                  // elaboration text for auth
    Authenticated,                      // auth successful
    Rejected(String),                   // auth failed with reason
}

// ============================================================================
// TCP FRAMING (from DIAGON)
// ============================================================================

const MAX_MESSAGE_SIZE: usize = 10_000_000;

fn write_auth_message(stream: &mut TcpStream, msg: &AuthMessage) -> io::Result<()> {
    let data = bincode::serialize(msg)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "Message too large"));
    }
    
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn read_auth_message(stream: &mut TcpStream) -> io::Result<AuthMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "Message too large"));
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    
    bincode::deserialize(&buf)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

// ============================================================================
// AUTHENTICATED CLIENT ACTOR
// ============================================================================

struct AuthClientActor {
    receiver: Receiver<AuthClientMessage>,
    stream: TcpStream,
    peer_addr: String,
    auth_state: AuthState,
    server_identity: Arc<ServerIdentity>,
}

struct AuthState {
    peer_did: Option<Did>,
    peer_pubkey: Option<Vec<u8>>,
    authenticated: bool,
    challenge: Option<[u8; 32]>,
    challenge_time: Option<Instant>,
}

enum AuthClientMessage {
    HandleAuth,
    ProcessData(Vec<u8>),
    Shutdown,
}

impl AuthClientActor {
    fn run(mut self) {
        // First, handle authentication
        match self.handle_authentication() {
            Ok(true) => {
                println!("[AUTH] {} authenticated successfully", self.peer_addr);
                // Transition to regular client actor behavior
                self.run_authenticated();
            }
            Ok(false) => {
                println!("[AUTH] {} authentication incomplete", self.peer_addr);
            }
            Err(e) => {
                println!("[AUTH] {} authentication failed: {}", self.peer_addr, e);
                let _ = write_auth_message(&mut self.stream, &AuthMessage::Rejected(e.to_string()));
            }
        }
    }
    
    fn handle_authentication(&mut self) -> io::Result<bool> {
        // Set timeout for auth phase
        self.stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        
        // Read initial Connect message
        let connect_msg = read_auth_message(&mut self.stream)?;
        
        match connect_msg {
            AuthMessage::Connect(peer_did, peer_pubkey, peer_pool) => {
                // Validate DID-pubkey binding
                if let Err(e) = self.validate_did_pubkey_binding(&peer_did, &peer_pubkey) {
                    return Err(io::Error::new(ErrorKind::InvalidData, e));
                }
                
                // Validate pool commitment
                if peer_pool != self.server_identity.pool_commitment {
                    return Err(io::Error::new(ErrorKind::PermissionDenied, "Pool mismatch"));
                }
                
                // Generate challenge
                let mut challenge = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut challenge);
                
                self.auth_state.peer_did = Some(peer_did);
                self.auth_state.peer_pubkey = Some(peer_pubkey);
                self.auth_state.challenge = Some(challenge);
                self.auth_state.challenge_time = Some(Instant::now());
                
                // Send challenge
                write_auth_message(&mut self.stream, &AuthMessage::Challenge(challenge))?;
                
                // Wait for response (signature)
                let response_msg = read_auth_message(&mut self.stream)?;
                
                match response_msg {
                    AuthMessage::Response(signature) => {
                        // Verify signature
                        if !self.verify_challenge_response(&signature)? {
                            return Err(io::Error::new(ErrorKind::PermissionDenied, "Invalid signature"));
                        }
                        
                        // Request elaboration
                        let elaborate_msg = read_auth_message(&mut self.stream)?;
                        
                        match elaborate_msg {
                            AuthMessage::Elaborate(text) => {
                                // Validate elaboration
                                if text.len() < 20 {
                                    return Err(io::Error::new(ErrorKind::InvalidData, 
                                        "Elaboration too short (min 20 chars)"));
                                }
                                
                                // Check challenge timeout (30 seconds for elaboration)
                                if let Some(challenge_time) = self.auth_state.challenge_time {
                                    if challenge_time.elapsed() > Duration::from_secs(30) {
                                        return Err(io::Error::new(ErrorKind::TimedOut, 
                                            "Challenge expired"));
                                    }
                                }
                                
                                // Authentication successful
                                self.auth_state.authenticated = true;
                                write_auth_message(&mut self.stream, &AuthMessage::Authenticated)?;
                                
                                println!("[AUTH] {} elaborated: {}", 
                                    self.auth_state.peer_did.as_ref().unwrap().0, 
                                    &text[..50.min(text.len())]);
                                
                                Ok(true)
                            }
                            _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected elaboration"))
                        }
                    }
                    _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected response"))
                }
            }
            _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected connect"))
        }
    }
    
    fn run_authenticated(mut self) {
        // Switch to non-blocking for main operation
        self.stream.set_nonblocking(true).expect("Failed to set non-blocking");
        self.stream.set_read_timeout(None).ok();
        
        let mut buffer = [0; 1024];
        
        println!("[AUTHENTICATED] {} entering main loop", 
            self.auth_state.peer_did.as_ref().unwrap().0);
        
        loop {
            // Check for control messages
            if let Ok(msg) = self.receiver.try_recv() {
                match msg {
                    AuthClientMessage::ProcessData(data) => {
                        println!("[DATA] Sending {} bytes to {}", 
                            data.len(), self.peer_addr);
                        if let Err(e) = self.stream.write_all(&data) {
                            eprintln!("[ERROR] Write failed: {:?}", e);
                            break;
                        }
                    }
                    AuthClientMessage::Shutdown => {
                        println!("[SHUTDOWN] {}", self.peer_addr);
                        break;
                    }
                    _ => {}
                }
            }
            
            // Try to read application data
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("[CLOSED] {}", self.peer_addr);
                    break;
                }
                Ok(n) => {
                    let data = buffer[0..n].to_vec();
                    println!("[RECV] {} bytes from {}", n, self.peer_addr);
                    
                    // Echo back
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("[ERROR] Echo write failed: {:?}", e);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("[ERROR] Read failed: {:?}", e);
                    break;
                }
            }
        }
        
        println!("[DISCONNECTED] {}", self.peer_addr);
    }
    
    fn validate_did_pubkey_binding(&self, did: &Did, pubkey_bytes: &[u8]) -> Result<(), String> {
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| "Invalid public key bytes")?;
        
        if Did::from_pubkey(&pubkey) != *did {
            return Err("DID does not match public key".into());
        }
        
        Ok(())
    }
    
    fn verify_challenge_response(&self, signature: &[u8]) -> io::Result<bool> {
        let challenge = self.auth_state.challenge
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "No active challenge"))?;
        
        let pubkey_bytes = self.auth_state.peer_pubkey.as_ref()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "No peer pubkey"))?;
        
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        
        let sig = DetachedSignature::from_bytes(signature)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        
        Ok(verify_detached_signature(&sig, &challenge, &pubkey).is_ok())
    }
}

// ============================================================================
// AUTHENTICATED CLIENT HANDLE
// ============================================================================

#[derive(Clone)]
struct AuthClientHandle {
    sender: Sender<AuthClientMessage>,
}

impl AuthClientHandle {
    fn new(stream: TcpStream, server_identity: Arc<ServerIdentity>) -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let peer_addr = stream.peer_addr()
            .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
        
        println!("[NEW CONNECTION] {}", peer_addr);
        
        let actor = AuthClientActor {
            receiver,
            stream,
            peer_addr,
            auth_state: AuthState {
                peer_did: None,
                peer_pubkey: None,
                authenticated: false,
                challenge: None,
                challenge_time: None,
            },
            server_identity,
        };
        
        thread::spawn(move || actor.run());
        
        Self { sender }
    }
    
    fn send_data(&self, data: Vec<u8>) -> Result<(), mpsc::SendError<AuthClientMessage>> {
        self.sender.send(AuthClientMessage::ProcessData(data))
    }
    
    fn shutdown(&self) -> Result<(), mpsc::SendError<AuthClientMessage>> {
        self.sender.send(AuthClientMessage::Shutdown)
    }
}

// ============================================================================
// SERVER IDENTITY MANAGEMENT
// ============================================================================

struct ServerIdentity {
    did: Did,
    public_key: PublicKey,
    secret_key: SecretKey,
    pool_commitment: [u8; 32],
    nonce_counter: Mutex<u64>,
}

impl ServerIdentity {
    fn load_or_create(addr: &str) -> io::Result<Arc<Self>> {
        create_dir_all("db").ok();
        
        let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
        let identity_path = format!("db/identity_{}.cbor", addr_hash);
        
        let (pk, sk, did) = if Path::new(&identity_path).exists() {
            // Load existing identity
            let data = std::fs::read(&identity_path)?;
            if let Ok((pk_bytes, sk_bytes, did)) = 
                serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                if let (Ok(pk), Ok(sk)) = (
                    PublicKey::from_bytes(&pk_bytes),
                    SecretKey::from_bytes(&sk_bytes)
                ) {
                    if Did::from_pubkey(&pk) == did {
                        (pk, sk, did)
                    } else {
                        let (pk, sk) = keypair();
                        let did = Did::from_pubkey(&pk);
                        (pk, sk, did)
                    }
                } else {
                    let (pk, sk) = keypair();
                    let did = Did::from_pubkey(&pk);
                    (pk, sk, did)
                }
            } else {
                let (pk, sk) = keypair();
                let did = Did::from_pubkey(&pk);
                (pk, sk, did)
            }
        } else {
            // Create new identity
            let (pk, sk) = keypair();
            let did = Did::from_pubkey(&pk);
            
            // Save identity
            let identity = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), did.clone());
            if let Ok(file) = File::create(&identity_path) {
                let _ = serde_cbor::to_writer(BufWriter::new(file), &identity);
            }
            
            (pk, sk, did)
        };
        
        println!("[IDENTITY] Server DID: {}", did.0);
        
        Ok(Arc::new(Self {
            did,
            public_key: pk,
            secret_key: sk,
            pool_commitment: [0; 32],  // Will be set with set_pool()
            nonce_counter: Mutex::new(0),
        }))
    }
    
    fn set_pool(&mut self, passphrase: &str) {
        self.pool_commitment = sha256(passphrase.as_bytes());
        println!("[POOL] Set to: {}", hex::encode(&self.pool_commitment[..8]));
    }
    
    fn generate_cid(&self, data: &[u8]) -> Cid {
        let mut counter = self.nonce_counter.lock().unwrap();
        *counter += 1;
        Cid::new(data, &self.did, *counter)
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        detached_sign(data, &self.secret_key).as_bytes().to_vec()
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// AUTHENTICATED SERVER MAIN
// ============================================================================

fn main() {
    let addr = std::env::args().nth(1)
        .unwrap_or_else(|| "0.0.0.0:9090".to_string());
    
    let pool = std::env::args().nth(2)
        .unwrap_or_else(|| "default_pool".to_string());
    
    // Initialize server identity
    let mut server_identity = ServerIdentity::load_or_create(&addr)
        .expect("Failed to load identity");
    
    // Set pool commitment from passphrase
    Arc::get_mut(&mut server_identity)
        .expect("Failed to get mutable reference")
        .set_pool(&pool);
    
    // Start packet capture if desired
    if std::env::var("CAPTURE").is_ok() {
        let capture_handle = CaptureHandle::new();
        capture_handle.start().expect("Failed to start capture");
    }
    
    // Start TCP listener
    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    println!("[SERVER] Listening on {} (pool: {})", addr, &pool);
    
    // Store authenticated client handles
    let clients = Arc::new(Mutex::new(Vec::<AuthClientHandle>::new()));
    
    // Accept loop
    for stream_result in listener.incoming() {
        if let Ok(stream) = stream_result {
            let handle = AuthClientHandle::new(stream, Arc::clone(&server_identity));
            clients.lock().unwrap().push(handle);
        }
    }
}

// ============================================================================
// CLIENT EXAMPLE
// ============================================================================

#[cfg(test)]
mod client_example {
    use super::*;
    
    pub fn connect_to_server(server_addr: &str, pool_passphrase: &str) -> io::Result<()> {
        // Load or create client identity
        let client_identity = ServerIdentity::load_or_create("client")?;
        Arc::get_mut(&mut client_identity.clone()).unwrap().set_pool(pool_passphrase);
        
        // Connect to server
        let mut stream = TcpStream::connect(server_addr)?;
        
        // Send Connect message
        let connect_msg = AuthMessage::Connect(
            client_identity.did.clone(),
            client_identity.public_key.as_bytes().to_vec(),
            client_identity.pool_commitment
        );
        write_auth_message(&mut stream, &connect_msg)?;
        
        // Receive challenge
        let challenge_msg = read_auth_message(&mut stream)?;
        
        match challenge_msg {
            AuthMessage::Challenge(nonce) => {
                // Sign challenge
                let signature = client_identity.sign(&nonce);
                write_auth_message(&mut stream, &AuthMessage::Response(signature))?;
                
                // Send elaboration
                let elaboration = "I am connecting to participate in the distributed knowledge network";
                write_auth_message(&mut stream, &AuthMessage::Elaborate(elaboration.to_string()))?;
                
                // Wait for authentication result
                let auth_result = read_auth_message(&mut stream)?;
                
                match auth_result {
                    AuthMessage::Authenticated => {
                        println!("[CLIENT] Authenticated successfully!");
                        // Now can use regular TCP for application protocol
                        Ok(())
                    }
                    AuthMessage::Rejected(reason) => {
                        Err(io::Error::new(ErrorKind::PermissionDenied, reason))
                    }
                    _ => Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response"))
                }
            }
            AuthMessage::Rejected(reason) => {
                Err(io::Error::new(ErrorKind::PermissionDenied, reason))
            }
            _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected challenge"))
        }
    }
}
```

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