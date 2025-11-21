# Start server in background
./target/release/tcp-server server 127.0.0.1:9090 test_pool &
SERVER_PID=$!
sleep 2

# Run client
./target/release/tcp-server client 127.0.0.1:9090 test_pool

# Cleanup
kill $SERVER_PID