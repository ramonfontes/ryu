#!/bin/bash

if [ "$1" == "h1" ]; then
    echo "running h3 on port 6653..."
    PYTHONPATH=. ./bin/ryu-manager --ofp-tcp-listen-port 6653 ryu/app/wifi.py
elif [ "$1" == "h2" ]; then
    echo "running h3 on port 6690..."
    PYTHONPATH=. ./bin/ryu-manager --ofp-tcp-listen-port 6690 ryu/app/wifi.py
elif [ "$1" == "h3" ]; then
    echo "running h3 on port 6691..."
    PYTHONPATH=. ./bin/ryu-manager --ofp-tcp-listen-port 6691 ryu/app/wifi.py
fi
