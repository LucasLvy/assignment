# Assignment

This repo contains a repo that will store any 32 bytes sent to it if the sender provides a valid signature of those bytes regarding his public key. The curve used here is ed25519.

## Run

First you'll need to start the server:

```sh
cargo r -r -p server
``````

Then you can start the client to have a small demo:

```sh
cargo r -r -p client
```

The output of the client should look like that:

```txt
Sending bytes to store
Sending bytes to store
Sending bytes to store
Sending bytes to store
Constructing a merkle tree from the data sent
Fetching the remote merkle root
Remote data isn't corrupted
Getting the state root and data
Verifying the state root against the data provided
Valid state root
```

The client will send 4 arrays of 32 bytes for the server to store. It will then query the merkle root of the server and verify it against its local merkle tree (built from the data it sent). Then it'll query the server to get the root and data to make sure that the data on the server is indeed used to build the tree.
