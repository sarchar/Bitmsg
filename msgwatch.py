from collections import deque
import gzip
import os
import sys
import time
import traceback

import base58
from bitcoin import Bitcoin
from common import *
from network import BitcoinNetwork
from transaction import Transaction

class Callbacks:
    TX_TIMEOUT = 4 * 60 * 60

    def __init__(self):
        self.watched_addresses = {}
        self.seen_transactions = set()
        self.seen_transactions_timeout = deque()
        self.rsa_private_keys = set()

    def watch_public(self):
        # Watch the public-message address
        key = b'\x00'
        address = addressgen.generate_address_from_data(key, version=0)
        self.watched_addresses[address] = (ENCRYPT_NONE, key)

    def watch_rc4(self, key):
        # Hash the key and add to watched addresses
        address = addressgen.generate_address_from_data(key, version=0)
        self.watched_addresses[address] = (ENCRYPT_RC4, key)

    def watch_aes128(self, key):
        # Hash the key and add to watched addresses
        address = addressgen.generate_address_from_data(key, version=0)
        self.watched_addresses[address] = (ENCRYPT_AES128, key)

    def watch_aes256(self, key):
        # Hash the key and add to watched addresses
        address = addressgen.generate_address_from_data(key, version=0)
        self.watched_addresses[address] = (ENCRYPT_AES256, key)

    def watch_rsa(self, private_key):
        self.rsa_private_keys.add(private_key)

    def will_request_transaction(self, txhash):
        now = time.time()

        while len(self.seen_transactions_timeout) and now > (self.seen_transactions_timeout[0][1] + Callbacks.TX_TIMEOUT):
            tx_hash, _ = self.seen_transactions_timeout.popleft()
            self.seen_transactions.remove(tx_hash)

        return txhash not in self.seen_transactions

    def check_tx_for_rsa(self, tx):
        # We need to check the transaction's first escrow output
        # for a keyblock.  
        
        # Find the first m-of-n output, building up message data
        data = []
        for i in range(0, len(tx.outputs)):
            output = tx.outputs[i]
            if output.address is None and output.multisig is not None:
                data.append(b''.join(k[1:] for k in output.multisig[0]))

        data = b''.join(data)

        if len(data) < 5:
            return None

        # Check the header for RSA encryption
        header, data = data[:5], data[5:]
        if header[0] < VERSION:
            return None

        if (header[1] & 0x7f) != ENCRYPT_RSA:
            return None
        
        # The next piece of the data is the encryption key block and has an
        # unknown number of keys
        if len(data) < 5:
            return None

        key_block_header, data = data[:5], data[5:]

        encrypted_key_block_size = struct.unpack('<L', key_block_header[1:5])[0]
        if len(data) < (encrypted_key_block_size - 5):
            return None

        compressed_encrypted_key_block = data[:encrypted_key_block_size]

        # Try to decompress the key block if necessary
        if (key_block_header[0] & 0x80) != 0:
            try:
                encrypted_key_block = gzip.decompress(compressed_encrypted_key_block)
            except:
                traceback.print_exc()
        else:
            encrypted_key_block = compressed_encrypted_key_block

        # Try to decrypt each of the keys
        for private_key in self.rsa_private_keys:
            i = 0
            rsa_block_size = private_key.size()
            while i <= (len(encrypted_key_block) - rsa_block_size):
                # First 2 bytes are a key size
                key_size = struct.unpack("<H", encrypted_key_block[i : i + 2])[0]
                i += 2

                if rsa_block_size != key_size:
                    i += key_size
                    continue

                encrypted_encryption_key = encrypted_key_block[i : i + rsa_block_size]
                try:
                    encryption_key = decrypt(private_key, encrypted_encryption_key, algorithm=ENCRYPT_RSA)
                    break
                except:
                    print(traceback.print_exc())
                    # We couldn't decrypt with this key, try the next one...
                    i += key_size
                    continue

            else:
                continue
            break
        else:
            return None

        return private_key, encryption_key, header, data[encrypted_key_block_size:]

    def got_transaction(self, tx):
        # Remember that we got this transaction for a little while
        now = time.time()
        tx_hash = tx.hash()
        self.seen_transactions.add(tx_hash)
        self.seen_transactions_timeout.append((tx_hash, now))

        # Check first output to see if it's delivered to the encryption address,
        # then check second and third address to see if it's something bound for
        # us. (If it's the third one, then the 2nd address is change).  The rest
        # of the addresses are part of the payload.
        if len(tx.outputs) < 3:
            return

        delivery = tx.outputs[0]
        delivery_address = delivery.getBitcoinAddress()
        msg_start_n = 1
        if delivery_address not in self.watched_addresses:
            delivery = tx.outputs[1]
            delivery_address = delivery.getBitcoinAddress()
            if delivery_address not in self.watched_addresses:
                if len(self.rsa_private_keys) != 0:
                    r = self.check_tx_for_rsa(tx)
                    if r is None:
                        return
                    rsa_private_key, key, header, encrypted_message = r
                    encryption_algorithm = header[1]

                    # TODO - use some kind of hash/id of the private key?
                    delivery_address = rsa_private_key
                else:
                    return
            else:
                msg_start_n = 2
                encryption_algorithm, key = self.watched_addresses[delivery_address]
        else:
            encryption_algorithm, key = self.watched_addresses[delivery_address]

        print('tx {} is for bitmsg'.format(Bitcoin.bytes_to_hexstring(tx_hash)))

        if encryption_algorithm in (ENCRYPT_NONE, ENCRYPT_RC4, ENCRYPT_AES128, ENCRYPT_AES256):
            # build the msg content
            header = None
            msg = []

            for k in range(msg_start_n, len(tx.outputs)):
                output = tx.outputs[k]
                if output.multisig is None or output.multisig[1] != 1:
                    return

                # Multisignature tx required here..
                assert all(120 >= len(pubkey) >= 33 for pubkey in output.multisig[0])
                payload = b''.join(k[1:] for k in output.multisig[0])

                if k == msg_start_n:
                    header, payload = payload[:5], payload[5:]

                    version = header[0]

                    if (header[1] & 0x7f) != encryption_algorithm:
                        # We can't decrypt this, says the header. The encryption algorithm doesn't match.
                        return

                    if header[4] != 0xff:
                        # TODO - handle reserved bits
                        return
                            
                if k == len(tx.outputs) - 1:
                    if header[3] != 0:
                        if header[3] >= PIECE_SIZE[version]:
                            # Invalid padding
                            return
                        payload = payload[:-header[3]]

                msg.append(payload)

            if header is None:
                return

            encrypted_message = b''.join(msg)

        # Determine the IV based on the first input
        input0 = tx.inputs[0]
        if (encryption_algorithm & 0x7f) == ENCRYPT_AES128:
            iv = (int.from_bytes(input0.tx_hash, 'big') % (1 << 128)).to_bytes(16, 'big')
        elif (encryption_algorithm & 0x7f) in (ENCRYPT_AES256, ENCRYPT_RSA):
            iv = (int.from_bytes(input0.tx_hash, 'big') % (1 << 256)).to_bytes(32, 'big')
        else:
            iv = None

        if (encryption_algorithm & 0x7f) == ENCRYPT_RSA:
            decrypted_message = decrypt(key, encrypted_message, ENCRYPT_AES256, iv=iv)
        else:
            decrypted_message = decrypt(key, encrypted_message, encryption_algorithm & 0x7f, iv=iv)

        if header[1] & 0x80:
            # Message is compressed
            decrypted_message = gzip.decompress(decrypted_message)

        print('-----Begin message to {}-----'.format(delivery_address))
        try:
            sys.stdout.write(decrypted_message.decode('utf8'))
        except UnicodeDecodeError:
            sys.stdout.write(repr(decrypted_message))
        print('\n-----End message-----')

def main():
    cb = Callbacks()

    # Handle some simple command-line arguments
    # -w Key : watch an RC4-encrypted channel
    # -p     : watch the Public unencrypted channel
    # -t tx  : try decoding and processing transaction 'tx' (hex)
    i = 1
    done = False
    while i < len(sys.argv):
        c = sys.argv[i]
        if c == '-w':
            i += 1
            cb.watch_rc4(sys.argv[i].encode('utf8'))
        elif c == '-a':
            i += 1
            cb.watch_aes128(sys.argv[i].encode('utf8'))
        elif c == '-p':
            cb.watch_public()
        elif c == '-r':
            i += 1
            private_key = load_private_key(open(sys.argv[i], 'rb').read().decode('ascii'))
            cb.watch_rsa(private_key)
        elif c == '-t':
            i += 1
            cb.got_transaction(Transaction.unserialize(Bitcoin.hexstring_to_bytes(sys.argv[i], reverse=False))[0])
            done = True
        else:
            print('invalid command line argument: {}'.format(c))
            return
        i += 1

    if done:
        return

    for addr in cb.watched_addresses.keys():
        print('Watching for messages to {}'.format(addr))

    # start network thread
    bitcoin_network = BitcoinNetwork(cb)
    bitcoin_network.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bitcoin_network.stop()
        bitcoin_network.join()
        raise

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit, Exception):
        traceback.print_exc()

