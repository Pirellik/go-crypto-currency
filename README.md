# go-crypto-currency
Crypto currency written in Go.

# Instructions
 - clone the repo:
 `git clone https://github.com/Pirellik/go-crypto-currency.git --recursive`
 - run clients:
 `docker-compose up`

This will start 3 network nodes with web intarfaces under following urls:
 - Node 1: http://localhost:4201/
 - Node 2: http://localhost:4202/
 - Node 3: http://localhost:4203/

To register single node in other's node network go to `Network nodes / Register in network` and type following url:
- http://go-crypto-1:9001 to register in Node 1's network
- http://go-crypto-2:9002 to register in Node 2's network
- http://go-crypto-3:9003 to register in Node 3's network

To stop the containers use  `Ctrl+C`. Have fun!