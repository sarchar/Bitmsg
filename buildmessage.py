from collections import defaultdict
import ctypes
import gzip
from http.client import HTTPConnection
import json
import math
import mimetypes
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
    message = None

    # Parse arguments first
    i = 1
    while i < len(sys.argv):
        v = sys.argv[1]
        if v == '-f':
            assert message is None, "you can only specify -f once"
            i += 1
            data = open(sys.argv[i], 'rb').read()
            mime_type, encoding = mimetypes.guess_type(sys.argv[i])

            if mime_type is not None:
                filename = os.path.basename(sys.argv[i])
                message = '\n'.join([
                    'Content-type: {}{}'.format(mime_type, '; charset={}'.format(encoding) if encoding is not None else ''),
                    'Content-length: {}'.format(len(data)),
                    'Content-disposition: attachment; filename={}'.format(filename),
                ])
                message = message.encode('utf8') + b'\n\n' + data

        i += 1

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

    # Select an encryption method
    while True:
        print('\n*** Step 4a. Select an encryption method:')
        print('...1. None (public message)')
        print('...2. RC4')
        print('...3. AES-128')
        print('...4. AES-256 (best)')
        print('...5. RSA (public-key)')
        try:
            i = int(input('? '))
            if i == 1:
                encryption_key = b'\x00'
                encryption_algorithm = ENCRYPT_NONE
            elif i == 2:
                required_key_length_message = "RC4 allows for variable-length keys, but longer is better"
                encryption_algorithm = ENCRYPT_RC4
            elif i == 3:
                required_key_length_message = "AES-128 requires a key length of 16 bytes"
                encryption_algorithm = ENCRYPT_AES128
            elif i == 4:
                required_key_length_message = "AES-256 requires a key length of 32 bytes"
                encryption_algorithm = ENCRYPT_AES256
            elif i == 5:
                required_key_length_message = "An RSA public-key is required"
                encryption_algorithm = ENCRYPT_RSA
            else:
                continue
            break
        except ValueError:
            continue

    if encryption_algorithm in (ENCRYPT_AES128, ENCRYPT_AES256, ENCRYPT_RC4):
        print('\n*** Step 4b. Provide an encryption key. The encryption key will be hashed and used as a Bitcoin address to designate the recipient.')
        encryption_key = input('...Enter an encryption key ({}): '.format(required_key_length_message)).encode('utf8')
        if encryption_algorithm == ENCRYPT_AES128 and len(encryption_key) != 16:
            print('...ERROR: key must have a length of 16 bytes.')
            return
        elif encryption_algorithm == ENCRYPT_AES256 and len(encryption_key) != 32:
            print('...ERROR: key must have a length of 32 bytes.')
            return
        elif encryption_algorithm == ENCRYPT_RC4 and len(encryption_key) == 0:
            print('...ERROR: key must not be empty')
            return
    elif encryption_algorithm == ENCRYPT_RSA:
        encryption_key = get_random_bytes(32)
        encrypted_rsa_encryption_keys = []
        while True:
            print('\n*** Step 4b. Provide the public-key for a recipient (in PEM form):\n')
            lines = []
            while True:
                line = input('')
                lines.append(line)
                if '-----END PUBLIC KEY-----' in line:
                    break
            public_key = load_public_key('\n'.join(lines))

            # encrypt encryption key
            encrypted_rsa_encryption_key = encrypt(public_key, encryption_key, algorithm=ENCRYPT_RSA)
            encrypted_rsa_encryption_keys.append(struct.pack('<H', len(encrypted_rsa_encryption_key)) + encrypted_rsa_encryption_key)

            answer = False
            while True:
                answer = input('...would you like to add another recipient? (y/N) ').strip().lower()
                if answer in ('y', 'yes'):
                    answer = True
                    break
                if answer in ('n', 'no', ''):
                    answer = False
                    break

            if not answer:
                break

    if encryption_algorithm == ENCRYPT_RSA:
        bitcoin_delivery_addresses = []
    else:
        bitcoin_delivery_addresses = [addressgen.generate_address_from_data(encryption_key, version=0)]

    print('...Message delivery to:')
    for bitcoin_delivery_address in bitcoin_delivery_addresses:
        print('... {}'.format(bitcoin_delivery_address))

    # Now we ask the user to enter a message
    if message is None:
        print('\n*** Step 5. Enter your message. End your message by entering \'.\' by itself on a new line.\n...Enter your message:\n')
        lines = []
        while True:
            line = input()
            if line == '.':
                break
            lines.append(line)
        message = '\n'.join(lines).encode('utf8')

        # Add some temporary headers
        message = 'Content-type: text/plain; charset=utf-8\nContent-length: {}\n\n'.format(len(message)).encode('ascii') + message

    # Try compressing the message before encryption, this may waste CPU but it's in the interest
    # of saving some outputs in the transaction.
    print('...Trying to compress the message...', end='')
    compressed_message = gzip.compress(message)
    if len(compressed_message) < len(message):
        print('good!')
        message = compressed_message
        encryption_algorithm |= 0x80
    else:
        print('not using because compressed version is larger.')

    # Setup the initialization vector using the first input's transaction id
    if (encryption_algorithm & 0x7f) == ENCRYPT_AES128:
        first_input = unspent_outputs[selected_inputs[0]]
        first_input_tx_hash = Bitcoin.hexstring_to_bytes(first_input['tx_hash'], reverse=False)
        iv = int.from_bytes(first_input_tx_hash, 'big')
        iv = (iv % (1 << 128)).to_bytes(16, 'big')
    elif (encryption_algorithm & 0x7f) in (ENCRYPT_AES256, ENCRYPT_RSA):
        # Bitcoin tx hashes are 32-bytes, so this is still OK for AES-256
        first_input = unspent_outputs[selected_inputs[0]]
        first_input_tx_hash = Bitcoin.hexstring_to_bytes(first_input['tx_hash'], reverse=False)
        iv = int.from_bytes(first_input_tx_hash, 'big')
        iv = (iv % (1 << 256)).to_bytes(32, 'big')
    else:
        iv = None

    # Encrypt the message
    if (encryption_algorithm & 0x7f) == ENCRYPT_RSA:
        encrypted_message = encrypt(encryption_key, message, algorithm=ENCRYPT_AES256, iv=iv)
    else:
        encrypted_message = encrypt(encryption_key, message, algorithm=(encryption_algorithm & 0x7f), iv=iv)

    # With RSA, the encrypted keys are compressed separately
    if (encryption_algorithm& 0x7f)  == ENCRYPT_RSA:
        print('...Trying to compress the key block...', end='')
        encrypted_key_block = b''.join(encrypted_rsa_encryption_keys)
        compressed_encrypted_key_block = gzip.compress(encrypted_key_block)
        if len(compressed_encrypted_key_block) < len(encrypted_key_block):
            print('good!')
            encrypted_key_block = b'\x80' + struct.pack('<L', len(compressed_encrypted_key_block)) + compressed_encrypted_key_block
        else:
            print('not using because compressed version is larger.')
            encrypted_key_block = b'\x00' + struct.pack('<L', len(encrypted_key_block)) + encrypted_key_block

        print('...Encrypted Key Block is {} bytes'.format(len(encrypted_key_block)))
        encrypted_message = encrypted_key_block + encrypted_message

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

    # setup the outputs. a trigger address isn't really needed, since the encryption
    # key can actually be used as the trigger (only those interested will be able to find
    # the message, anyway)

    # cost of the transaction is (targets + pieces/3 + sacrifice) * SPECIAL_SATOSHI
    # peices/3 because we include 3 pieces per output
    outputs_count = (len(bitcoin_delivery_addresses) + math.ceil(len(bitcoin_message_pieces) / 3))
    approx_tx_cost = MINIMUM_SACRIFICE + outputs_count * SPECIAL_SATOSHI
    if approx_tx_cost > total_input_amount:
        raise Exception("not enough inputs provided")

    tx_change_output = None
    tx_change_output_n = None
    if total_input_amount > approx_tx_cost:
        print('...output (change) to {}'.format(bitcoin_change_address))
        tx_change_output = TransactionOutput(bitcoin_change_address, amount=total_input_amount - approx_tx_cost)
        tx_change_output_n = tx.addOutput(tx_change_output)

    # The recipient will know how to handle this if they see their key...
    for i, bitcoin_delivery_address in enumerate(bitcoin_delivery_addresses):
        print('...output (target) to {}'.format(bitcoin_delivery_address))
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

        print('...output (message) to multisig 1-of-{}{}'.format(len(pieces), ' (header={})'.format(header) if header is not None else ''))
        tx_output = TransactionOutput(amount=SPECIAL_SATOSHI)
        tx_output.setMultisig(pieces, 1)
        tx.addOutput(tx_output)

    # we should now be able to figure out how much in fees is required now that the tx is built
    recommended_fee = max(MINIMUM_SACRIFICE * SPECIAL_SATOSHI, tx.getRecommendedTransactionFee(per_kb=SACRIFICE_PER_KB))
    recommended_tx_cost = recommended_fee + outputs_count * SPECIAL_SATOSHI
    if recommended_tx_cost > total_input_amount:
        raise Exception("not enough inputs provided ({} BTC required)".format(Bitcoin.format_money(recommended_tx_cost)))
    
    if tx_change_output is not None and recommended_tx_cost == total_input_amount:
        # We can remove the output
        tx.removeOutput(tx_change_output_n)
        tx_change_output = None
        
    if recommended_tx_cost < total_input_amount:
        if tx_change_output is None:
            print('...output (change) to {}'.format(bitcoin_change_address))
            tx_change_output = TransactionOutput(bitcoin_change_address)
            tx_change_output_n = tx.addOutput(tx_change_output)
        tx_change_output.amount = total_input_amount - recommended_tx_cost

    print('...the fee for this transaction is {} BTC'.format(Bitcoin.format_money(tx.totalInput() - tx.totalOutput())))
    print('...the total sent is {} BTC (change = {})'.format(Bitcoin.format_money(tx.totalInput()), Bitcoin.format_money(0 if tx_change_output is None else tx.outputs[tx_change_output_n].amount)))
    
    # sign all inputs
    tx.sign()

    print('...the transaction is {} bytes.'.format(tx.size()))

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

