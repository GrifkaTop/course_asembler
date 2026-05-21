#!/bin/bash
cd /home/grifka/vsCode/course_asembler/build
pkill -9 -x server 2>/dev/null
sleep 0.3
rm -f data.bin alice.key bob.key charlie.key diana.key tester*.key
./server &>server.log &
sleep 0.5
python3 "${1:-test.py}"
