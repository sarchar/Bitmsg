from collections import defaultdict
import ctypes
import gzip
from http.client import HTTPConnection
import json
import os
import sys
import traceback

import addressgen
import base58
from bitcoin import Bitcoin
from common import *
import script
from transaction import Transaction, TransactionInput, TransactionOutput

def lookup_unspent_outputs(bitcoin_addresses):
    conn = HTTPConnection('blockchain.info')
    conn.request('GET', '/unspent?active={}'.format('|'.join(bitcoin_addresses)))
    result = json.loads(conn.getresponse().read().decode('utf8'))
    unspent = defaultdict(list)

    for u in result['unspent_outputs']:
        program_bytes = Bitcoin.hexstring_to_bytes(u['script'], reverse=False)
        scriptPubKey, _ = script.Script.unserialize(program_bytes, len(program_bytes))
        address = None

        # Try to extract the address from the scriptpubkey program
        if len(scriptPubKey.program) == 6 and \
           scriptPubKey.program[0][0] == script.OP_DUP and scriptPubKey.program[1][0] == script.OP_HASH160 and \
           scriptPubKey.program[2][0] == 20 and \
           scriptPubKey.program[4][0] == script.OP_EQUALVERIFY and scriptPubKey.program[5][0] == script.OP_CHECKSIG:
                address = scriptPubKey.program[3]
        elif len(scriptPubKey.program) == 3 and scriptPubKey.program[2][0] == script.OP_CHECKSIG:
            if scriptPubKey.program[2][0] in (0x04, 0x03, 0x02):
                address = base58.decode_to_bytes(addressgen.generate_address(scriptPubKey.program[1], version=0))[-24:-4]

        if address is not None:
            i = 0
            while address[i] == 0:
                i += 1
            address = '1' + ('1' * i) + addressgen.base58_check(address, version=0)
            unspent[address].append(u)
    return unspent

def filter_unspent_outputs(unspent_outputs):
    # TODO: filter based on confirmations, value, etc?
    return unspent_outputs

def push_transaction(serialized_tx):
    conn = HTTPConnection('blockchain.info')
    body = 'tx=' + ''.join(Bitcoin.bytes_to_hexstring(serialized_tx, reverse=False))
    body = body.encode('ascii')
    conn.request('POST', '/pushtx', body=body, headers={'Content-Length': len(body), 'Content-type': 'application/x-www-form-urlencoded'})
    result = conn.getresponse().read()
    if b'Submitted' in result:
        return True
    else:
        try:
            return result.decode('utf8')
        except:
            return "Unknown error"

def main():
    # Get coins for input
    print('*** Step 1. We need Bitcoins in order to send a message. Give me a Bitcoin private key (it starts with a 5...) to use as an input for the message transaction.')
    bitcoin_private_key = input('...Enter Bitcoin private key: ')

    # Decode private key, show bitcoin address associated with key
    private_key = base58.decode_to_bytes(bitcoin_private_key)[-36:-4]
    public_key = addressgen.get_public_key(private_key)
    bitcoin_input_address = addressgen.generate_address(public_key, version=0)
    print('...The Bitcoin address associated with that private key is: {}'.format(bitcoin_input_address))

    # Lookup the unspent outputs associated with the given input...
    print('...Looking up unspent outputs on blockchain.info...')
    unspent_outputs = filter_unspent_outputs(lookup_unspent_outputs([bitcoin_input_address])[bitcoin_input_address])

    # Show the inputs to the user, and ask him which he'd like to use as input.
    print('\n*** Step 2. You need to select an input:')
    for k, u in enumerate(unspent_outputs):
        print('...{}: txid={} n={} value={} confirmations={}'.format(k+1, u['tx_hash'], u['tx_output_n'], Bitcoin.format_money(u['value']), u['confirmations']))
    selected_inputs = [int(x.strip())-1 for x in input('Enter inputs (if more than one, separated by commas): ').split(',') if len(x) > 0]
    if not all(x >= 0 and x < len(unspent_outputs) for x in selected_inputs):
        raise Exception("Invalid input provided")
    total_input_amount = sum(unspent_outputs[k]['value'] for k in selected_inputs)
    print('...{} BTC selected from {} input{}'.format(Bitcoin.format_money(total_input_amount), len(selected_inputs), 's' if len(selected_inputs) != 1 else ''))

    # Ask the user for the change address, defaulting to the same input address
    print('\n*** Step 3. Provide a change address (this will not be used if a change address isn\'t necessary)')
    bitcoin_change_address = input('...Enter change address (leave blank to use the input address as the change address): ').strip()
    if len(bitcoin_change_address) == 0:
        bitcoin_change_address = bitcoin_input_address
        print('...Change address: {}'.format(bitcoin_change_address))

    # We need a recipient:
    print('\n*** Step 4. Provide an encryption key. The encryption key will be hashed and used as a Bitcoin address to designate the recipient. The current implementation uses RC4, so longer keys are better.')
    encryption_key = input('...Enter an encryption key (leave blank for no encryption): ')
    if len(encryption_key) == 0:
        encryption_key = b'\x00'
        encryption_algorithm = 0
    else:
        encryption_key = encryption_key.encode('utf8')
        encryption_algorithm = 1

    bitcoin_delivery_address = addressgen.generate_address_from_data(encryption_key, version=0)
    print('...Message delivery to: {}'.format(bitcoin_delivery_address))

    # Now we ask the user to enter a message
    print('\n*** Step 5. Enter your message. End your message by entering \'.\' by itself on a new line.\n...Enter your message:\n')
    lines = []
    while True:
        line = input()
        if line == '.':
            break
        lines.append(line)
    message = '\n'.join(lines).encode('utf8')

    # Try compressing the message before encryption, this may waste CPU but it's in the interest
    # of saving some outputs in the transaction.
    print('...Trying to compress the message...', end='')
    compressed_message = gzip.compress(message)
    if len(compressed_message) < len(message):
        print('good!')
        message = compressed_message
        encryption_algorithm |= 0x80
    else:
        print('throwing away.')

    # Encrypt the message
    encrypted_message = encrypt(encryption_key, message, algorithm=(encryption_algorithm & 0x7f))
    print('...Encrypted message is {} bytes'.format(len(encrypted_message)))

    # Build the message header. Prefix the encrypted message with the header.
    checksum             = sum(encrypted_message) % 256
    reserved             = 0xff
    padding              = 0
    header               = bytes([VERSION, encryption_algorithm, checksum, padding, reserved])
    encrypted_message    = header + encrypted_message

    # Split the encrypted message into pubkeys. We get 119 bytes per pubkey (we reserve
    # the first byte in case any future changes to bitcoind require a valid pubkey)
    bitcoin_message_pieces = []
    for i in range(0, len(encrypted_message), PIECE_SIZE[VERSION]):
        piece = encrypted_message[i:i+PIECE_SIZE[VERSION]]
        bitcoin_message_pieces.append(b'\xff' + piece)

    if len(bitcoin_message_pieces) == 1 and len(bitcoin_message_pieces[0]) < 33:
        # This is the only case where we need padding in version 2 messages.
        padding = 33 - len(bitcoin_message_pieces[0])
        bitcoin_message_pieces[0] = bitcoin_message_pieces[0] + bytes([padding] * padding)

        # We have to adjust the header 'padding' value
        bitcoin_message_pieces[0] = bitcoin_message_pieces[0][:4] + bytes([padding]) + bitcoin_message_pieces[0][5:]
    elif len(bitcoin_message_pieces) > 1 and len(bitcoin_message_pieces[-1]) < 33:
        # We shift however many bytes out of the 2nd to last block and into the last one
        # to make sure it's at least 33 bytes long
        req = 33 - len(bitcoin_message_pieces[-1])
        bitcoin_message_pieces[-1] = bytes([bitcoin_message_pieces[-1][0]]) + bitcoin_message_pieces[-2][-req:] + bitcoin_message_pieces[-1][1:]
        bitcoin_message_pieces[-2] = bitcoin_message_pieces[-2][:-req]
        assert 120 >= len(bitcoin_message_pieces[-2]) >= 33 and 120 >= len(bitcoin_message_pieces[-1]) >= 33

    # start building the transaction
    tx = Transaction()

    # setup the inputs
    for n, k in enumerate(selected_inputs):
        unspent = unspent_outputs[k]
        tx_input = TransactionInput(tx_hash=Bitcoin.hexstring_to_bytes(unspent['tx_hash'], reverse=False), 
                                    tx_output_n=unspent['tx_output_n'],
                                    scriptPubKey=Bitcoin.hexstring_to_bytes(unspent['script'], reverse=False),
                                    amount=unspent['value'],
                                    signing_key=private_key)
        print('...input {} is {} BTC from {}'.format(n, Bitcoin.format_money(unspent['value']), bitcoin_input_address))
        tx.addInput(tx_input)

    # setup the outputs
    print('...output (trigger)  0 to {}'.format(MESSAGE_ADDRESS_CURRENT_VERSION_TRIGGER))
    tx_output = TransactionOutput(MESSAGE_ADDRESS_CURRENT_VERSION_TRIGGER, amount=SPECIAL_SATOSHI)
    tx.addOutput(tx_output)

    # cost of the transaction is (trigger + delivery + pieces/3 + sacrifice) * SPECIAL_SATOSHI
    # peices/3 because we include 3 pieces per output
    tx_cost = (2 + (int(len(bitcoin_message_pieces) / 3 + 0.5)) + SACRIFICE) * SPECIAL_SATOSHI
    if tx_cost > total_input_amount:
        raise Exception("not enough inputs provided")

    if total_input_amount > tx_cost:
        print('...output (change)   1 to {}'.format(bitcoin_change_address))
        tx_output = TransactionOutput(bitcoin_change_address, amount=total_input_amount - tx_cost)
        tx.addOutput(tx_output)

    # The recipient will know how to handle this if they see their key...
    print('...output (delivery) 2 to {}'.format(bitcoin_delivery_address))
    tx_output = TransactionOutput(bitcoin_delivery_address, amount=SPECIAL_SATOSHI)
    tx.addOutput(tx_output)

    for i in range(0, len(bitcoin_message_pieces), 3):
        pieces = bitcoin_message_pieces[i:i+3]

        d = b''.join([p[1:] for p in pieces])
        header = None
        if i == 0:
            header = d[:5]
            d = d[5:]
        if (i + 3) >= len(bitcoin_message_pieces):
            if padding > 0:
                d = d[:-padding]

        print('...output (message) {} to multisig 1-of-{} ({}bytes={})'.format(3+i//3, len(pieces), 'header={}, '.format(header) if header is not None else '', d))
        tx_output = TransactionOutput(amount=SPECIAL_SATOSHI)
        tx_output.setMultisig(pieces, 1)
        tx.addOutput(tx_output)

    # sign all inputs
    tx.sign()

    # Finally, do something with the transaction
    print('\n*** Step 6. The transaction is built. What would you like to do with it?')
    while True:
        print('...1. Show JSON')
        print('...2. Show HEX')
        print('...3. Push (via blockchain.info/pushtx)')
        print('...4. Quit')
        try:
            command = int(input('? ')) - 1
            assert command >= 0 and command < 4

            if command == 0:
                print(json.dumps(tx.as_dict()))
            elif command == 1:
                print(Bitcoin.bytes_to_hexstring(tx.serialize(), reverse=False))
            elif command == 2:
                err = push_transaction(tx.serialize())
                if isinstance(err, bool):
                    print("...pushed {}".format(Bitcoin.bytes_to_hexstring(tx.hash())))
                else:
                    print("...error pushing:", err)
            elif command == 3:
                break
        except EOFError:
            break
        except:
            print('Try again.')
            pass

    print("...exiting")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit, Exception):
        traceback.print_exc()

