#!/bin/bash

echo "=== DGTCP ==="

# Start server
./target/release/tcp-server server 127.0.0.1:9090 test_pool &
SERVER_PID=$!

# Wait for server startup
sleep 2

# Run client test
./target/release/tcp-server client 127.0.0.1:9090 test_pool
CLIENT_EXIT=$?

# Cleanup
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

# Report
echo ""
echo "=== Test Complete ==="
if [ $CLIENT_EXIT -eq 0 ]; then
    echo "✓ All tests passed"
    exit 0
else
    echo "✗ Client failed with exit code $CLIENT_EXIT"
    exit 1
fi