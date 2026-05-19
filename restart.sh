#!/bin/bash
pkill -f build/server 2>/dev/null
sleep 0.5
fuser -k 8080/tcp 2>/dev/null
sleep 0.3
nohup ./build/server > /dev/null 2>&1 &
sleep 1
echo "Сервер запущен на порту 8080"
