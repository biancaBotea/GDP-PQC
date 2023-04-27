cat $1 | grep -i "Handshake Latency:\|^[[:blank:]]*$" | sed s/'   Handshake Latency: '//
