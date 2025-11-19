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
