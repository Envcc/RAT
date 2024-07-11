#!/bin/bash

# Compile the RAT client
echo "Compiling RAT client..."
cd RAT_Client
./compile_rat.sh
cd ..

# Run the C2 server
echo "Starting C2 server..."
cd C2_Server
./run_server.sh &
SERVER_PID=$!
cd ..

# Run the RAT client with a test command
echo "Running RAT client with test command..."
cd RAT_Client
./run_rat.sh "test_command"
cd ..

# Wait for the server to process
sleep 10

# Cleanup
echo "Stopping C2 server..."
kill $SERVER_PID
echo "Automation complete."
