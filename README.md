# scanner
network scanner for learning various things

The c directory contains work around using raw sockets, mostly derrived from Internet examples and not functioning as intended.

The node directory contains an npm package titled "tcp-connscan" which is published and can be installed with:

 npm install -g tcp-connscan

At some point I should test this works in linux without having to install the node -> nodejs symlink (I bet it doesn't).

The tcp-connscan program can be run like so:

 tcp-connscan <address>

This command will attempt to open a tcp connection to all 2^16 - 1 tcp ports using as many child processes as the running system has CPU's.
