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