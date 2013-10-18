Bitmsg
======

Bitmsg is a utility to publish and receive encrypted messages via the Bitcoin
network. No proof of work is necessary due to the fact that publishing messages
requires payment to the network, i.e., sacrifice.

Requirements
============

Bitmsg is only tested on Windows using Python 3.3 32-bit. You need A copy of
libeay32.dll (obtained from the OpenSSL packages for Windows or built
yourself).

The code has very few dependencies so should be trivial to port to Linux,
MacOS, etc.

Usage
=====

There are two programs of note: buildmessage.py and msgwatch.py.  The rest of
the files in this archive are support modules for Bitcoin and related code.

To send a message
-----------------

Run "python buildmessage.py" and provide the information asked of you.

To receive messages
-------------------

The program msgwatch.py is used to connect to the Bitcoin network and monitor
transactions that are floating around.  The arguments to pass to msgwatch.py
will help determine which messages you are able to receive.

* -p : This will listen on the network for unencrypted, public messages.
* -w key : This will listen on the network for encrypted (RC4) messages. You can specify '-w' multiple times.
* -a key : This will listen on the network for encrypted (AES-128) messages. You can specify '-a' multiple times. AES-128 keys must be 16 bytes in length.

For example, "python msgwatch.py -p -w general -a mysecretkeyhello" will listen for messages that
are encrypted with RC4 using the phrase "general" and with AES-128 using mysecretkeyhello.

TODO
====

Some important tasks left to be done include:

* Proper internet message formatting
* Parsing blocks and blockchain for transactions that were missed while offline
* Relaying blocks and transactions
* More configurable things such as the amount to sacrifice
* Zero-bitcoin outputs (but this creates non-standard txns)
* I would like all coins to be sacrificed (except change) to miners instead of throwing away a Satoshi for each output
* Obscure the fact the transactions are messages by changing the trigger addressed based on the encryption key as well as use less predictable amounts for the outputs
* Encryption using ECC (using Bitcoin pub/priv keypairs)
