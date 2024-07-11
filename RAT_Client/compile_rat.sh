#!/bin/bash
gcc -o rat_client rat_client.c -lssl -lcrypto
echo "RAT client compiled successfully."
