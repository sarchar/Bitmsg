import hashlib
import struct

import addressgen
from bitcoin import Bitcoin
from script import *
import base58

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

class TransactionOutput:
    BEHAVIOR_STRANGE     = 0x8000

    def __init__(self, address=None, amount=0):
        self.amount = amount
        self.address = base58.decode_to_bytes(address)[-24:-4] if address is not None else None
        self.multisig = None

        self.scriptPubKey = None

    def setMultisig(self, pubkeys, required_signatures):
        self.multisig     = (pubkeys, required_signatures)
        self.address      = None
        self.scriptPubKey = None

    def createOutputScript(self):
        if self.scriptPubKey is not None:
            return

        self.scriptPubKey = Script()
        self.scriptPubKey.clear()

        if self.multisig is not None:
            self.scriptPubKey.pushOp(OP_1 + self.multisig[1] - 1)
            for key in self.multisig[0]:
                self.scriptPubKey.pushData(key)
            assert len(self.multisig[0]) <= 16
            self.scriptPubKey.pushOp(OP_1 + len(self.multisig[0]) - 1)
            self.scriptPubKey.pushOp(OP_CHECKMULTISIG)
            #self.scriptPubKey.pushOp(OP_VERIFY)
        else:
            assert self.address is not None
            self.scriptPubKey.pushOp(OP_DUP)
            self.scriptPubKey.pushOp(OP_HASH160)
            self.scriptPubKey.pushData(self.address)
            self.scriptPubKey.pushOp(OP_EQUALVERIFY)
            self.scriptPubKey.pushOp(OP_CHECKSIG)

    def extractAddressFromOutputScript(self):
        self.address = None

        if len(self.scriptPubKey.program) == 6 and \
           self.scriptPubKey.program[0][0] == OP_DUP and self.scriptPubKey.program[1][0] == OP_HASH160 and \
           self.scriptPubKey.program[2][0] == 20 and \
           self.scriptPubKey.program[4][0] == OP_EQUALVERIFY and self.scriptPubKey.program[5][0] == OP_CHECKSIG:
                self.address = self.scriptPubKey.program[3]
                assert len(self.address) == 20
        elif len(self.scriptPubKey.program) == 3 and \
            self.scriptPubKey.program[2][0] == OP_CHECKSIG:
                if self.scriptPubKey.program[2][0] in (0x04, 0x03, 0x02):
                    self.address = base58.decode_to_bytes(addressgen.generate_address(self.scriptPubKey.program[1]))[-24:-4]
        elif self.scriptPubKey.program[-1][0] == OP_CHECKMULTISIG:
            nreq = self.scriptPubKey.program[0][0] - OP_1 + 1
            nkeys = self.scriptPubKey.program[-2][0] - OP_1 + 1
            if nreq >= 1 and nreq <= nkeys:
                pubkeys = [self.scriptPubKey.program[2 + i * 2] for i in range(nkeys)]
                self.multisig = (pubkeys, nreq)

    def serializeForSignature(self, hashType):
        return self.serialize()

    def getBitcoinAddress(self):
        j = 0
        while self.address[j] == 0:
            j += 1

        return ('1' + ('1' * j) + addressgen.base58_check(self.address)) if self.address is not None else None

    def serialize(self):
        self.createOutputScript()

        data_list = []

        data_list.append(struct.pack("<Q", self.amount))
        script_bytes = self.scriptPubKey.serialize()
        data_list.append(Bitcoin.serialize_variable_int(len(script_bytes)))
        data_list.append(script_bytes)

        return b''.join(data_list)

    def serialize_size(self):
        self.createOutputScript()

        data_size = 0

        data_size += 8
        script_bytes = self.scriptPubKey.serialize_size()
        data_size += Bitcoin.serialize_variable_int_size(script_bytes)
        data_size += script_bytes

        return data_size

    @staticmethod
    def unserialize(data):
        txn_output = TransactionOutput()
        txn_output.amount = struct.unpack("<Q", data[:8])[0]
        script_size, data = Bitcoin.unserialize_variable_int(data[8:])
        txn_output.scriptPubKey, data = Script.unserialize(data, script_size)
        txn_output.extractAddressFromOutputScript()
        return txn_output, data

class TransactionInput:
    def __init__(self, tx_hash=None, tx_output_n=None, scriptPubKey=None, amount=None, seq=0xffffffff, signing_key=None):
        # Out point
        self.n = tx_output_n
        self.tx_hash = tx_hash
        self.sequence = seq
        self.scriptPubKey = scriptPubKey
        self.scriptSig = Script()
        self.input = amount
        self.signing_key = signing_key
        self.signed = False
        self.address = None

    def createScriptSig(self, hashType, signHash):
        assert self.signing_key is not None

        self.scriptSig.clear()

        signature = addressgen.ecdsa_sign(self.signing_key, signHash)
        signature = signature + struct.pack("<B", hashType)
        #print("signature: {}".format(''.join(['{:02x}'.format(x) for x in signature])))

        self.scriptSig.pushData(signature)

        public_key = addressgen.get_public_key(self.signing_key)
        self.scriptSig.pushData(public_key)

        if self.address is None:
            self.extractAddressFromInputScript()

        self.signed = True
        self.signed_hash_type = hashType

    def clearScriptSig(self):
        self.scriptSig.clear()
        self.signed = False

    def extractAddressFromInputScript(self):
        self.address = None
        self.signed = False
        if len(self.scriptSig.program) == 4 and len(self.scriptSig.program[1]) in (71, 72, 73):
            if len(self.scriptSig.program[3]) in (33,65):
                self.address = base58.decode_to_bytes(addressgen.generate_address(self.scriptSig.program[3]))[-24:-4]

                # TODO - we have to run the script to see if the signature is valid for the input, but for now we just accept if it has non-zero length
                self.signed = True
                self.signed_hash_type = self.scriptSig.program[1][-1]

    def getBitcoinAddress(self):
        j = 0
        while self.address[j] == 0:
            j += 1

        return ('1' + ('1' * j) + addressgen.base58_check(self.address)) if self.address is not None else None

    def serializeForSignature(self, hashType, selfSig):
        data_list = []
        data_list.append(self.tx_hash)
        data_list.append(struct.pack("<L", self.n))

        if selfSig:
            script_bytes = self.scriptPubKey
        else:
            script_bytes = b''

        data_list.append(Bitcoin.serialize_variable_int(len(script_bytes)))
        data_list.append(script_bytes)

        if selfSig or (hashType & ~SIGHASH_ANYONECANPAY) != SIGHASH_NONE:
            data_list.append(struct.pack("<L", self.sequence))
        else:
            data_list.append(struct.pack("<L", 0))

        return b''.join(data_list)

    def serialize(self):
        data_list = []
        data_list.append(self.tx_hash)
        data_list.append(struct.pack("<L", self.n))

        script_bytes = self.scriptSig.serialize()
        data_list.append(Bitcoin.serialize_variable_int(len(script_bytes)))
        data_list.append(script_bytes)

        data_list.append(struct.pack("<L", self.sequence))

        return b''.join(data_list)

    def serialize_size(self):
        data_size = 0
        data_size += 32
        data_size += 4

        script_bytes = self.scriptSig.serialize_size()
        data_size += Bitcoin.serialize_variable_int_size(script_bytes)
        data_size += script_bytes

        data_size += 4
        return data_size

    @staticmethod
    def unserialize(data, as_coinbase=False):
        txn_input = TransactionInput()
        txn_input.tx_hash = data[:32]
        txn_input.n = struct.unpack("<L", data[32:36])[0]

        script_size, data = Bitcoin.unserialize_variable_int(data[36:])
        txn_input.scriptSig, data = Script.unserialize(data, script_size, as_coinbase=as_coinbase)
        txn_input.extractAddressFromInputScript()

        txn_input.sequence = struct.unpack("<L", data[:4])[0]

        return txn_input, data[4:]

class Transaction:
    TRANSACTION_TYPE_PAYMENT_NORMAL = 0
    TRANSACTION_TYPE_PAYMENT_ANYONECANPAY = 1

    CURRENT_VERSION = 1

    CHECK_VALID = 1
    CHECK_NONSTANDARD = 2
    CHECK_INVALID = 3

    def __init__(self, transactionType=TRANSACTION_TYPE_PAYMENT_NORMAL):
        self.version = Transaction.CURRENT_VERSION
        self.lock_time = 0
        self.inputs = []
        self.outputs = []
        self.type = transactionType

    def addInput(self, txn_input):
        self.inputs.append(txn_input)

    def removeInput(self, n):
        self.inputs = self.inputs[:n] + self.inputs[n+1:]
        if self.type == Transaction.TRANSACTION_TYPE_PAYMENT_NORMAL:
            for i in self.inputs:
                i.clearScriptSig()

    def addOutput(self, txn_output):
        self.outputs.append(txn_output)
        r = len(self.outputs) - 1

        if self.type == Transaction.TRANSACTION_TYPE_PAYMENT_NORMAL:
            for i in self.inputs:
                i.clearScriptSig()

        return r

    def setOutputAmount(self, index, amount):
        self.outputs[index].amount = amount

    def totalInput(self):
        return sum(i.input if i.input is not None else 0 for i in self.inputs)

    def totalOutput(self):
        return sum(o.amount for o in self.outputs)

    def check(self):
        # TODO - check valid inputs/outputs/signatures/etc
        return Transaction.CHECK_VALID

    def signed(self, n=None):
        if n is None:
            return all(i.signed for i in self.inputs)
        else:
            return self.inputs[n].signed

    def sign(self, n=None):
        if self.type == Transaction.TRANSACTION_TYPE_PAYMENT_NORMAL:
            hashType = SIGHASH_ALL
        elif self.type == Transaction.TRANSACTION_TYPE_PAYMENT_ANYONECANPAY:
            hashType = SIGHASH_ANYONECANPAY | SIGHASH_ALL

        # For each input, create the signature script
        for i, input in enumerate(self.inputs):
            if n is None or i == n:
                signHash = self.hashForSignature(i, hashType)
                input.createScriptSig(hashType, signHash)

        # TODO - verify/run scripts ?

    def hashForSignature(self, inputIndex, hashType):
        d = self.serializeForSignature(inputIndex, hashType)
        hasher = hashlib.sha256()
        hasher.update(d)
        hasher2 = hashlib.sha256()
        hasher2.update(hasher.digest())
        return hasher2.digest()

    def serializeForSignature(self, inputIndex, hashType):
        data_list = []
        data_list.append(struct.pack("<L", self.version))

        if (hashType & SIGHASH_ANYONECANPAY) != 0:
            data_list.append(Bitcoin.serialize_variable_int(1))
            data_list.append(self.inputs[inputIndex].serializeForSignature(hashType, True))
        else:
            data_list.append(Bitcoin.serialize_variable_int(len(self.inputs)))
            for i, input in enumerate(self.inputs):
                data_list.append(input.serializeForSignature(hashType, i == inputIndex))

        # outputs
        if (hashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_NONE:
            data_list.append(Bitcoin.serialize_variable_int(0))
        elif (hashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_ALL:
            data_list.append(Bitcoin.serialize_variable_int(len(self.outputs)))
            for i, output in enumerate(self.outputs):
                data_list.append(output.serializeForSignature(hashType))
        elif (hashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE:
            data_list.append(Bitcoin.serialize_variable_int(1))
            assert inputIndex < len(self.outputs)
            data_list.append(self.outputs[inputIndex].serializeForSignature(hashType))

        data_list.append(struct.pack("<L", self.lock_time))

        data_list.append(struct.pack("<L", hashType))

        return b''.join(data_list)

    def hash(self):
        return Bitcoin.hash(self.serialize())

    def serialize(self):
        data_list = []
        data_list.append(struct.pack("<L", self.version))

        data_list.append(Bitcoin.serialize_variable_int(len(self.inputs)))
        for i, input in enumerate(self.inputs):
            data_list.append(input.serialize())

        data_list.append(Bitcoin.serialize_variable_int(len(self.outputs)))
        for i, output in enumerate(self.outputs):
            data_list.append(output.serialize())

        data_list.append(struct.pack("<L", self.lock_time))

        return b''.join(data_list)
    
    def serialize_size(self):
        data_size = 0
        data_size += 4

        data_size += Bitcoin.serialize_variable_int_size(len(self.inputs))
        for i, input in enumerate(self.inputs):
            data_size += input.serialize_size()

        data_size += Bitcoin.serialize_variable_int_size(len(self.outputs))
        for i, output in enumerate(self.outputs):
            data_size += output.serialize_size()

        data_size += 4
        return data_size

    def size(self):
        return len(self.serialize())

    def getRecommendedTransactionFee(self):
        # TB - This is ripped off from bitcoind, main.cpp, GetMinFee

        # TB TODO - Regular TX vs relay TX
        MIN_TX_FEE = 10000
        MIN_RELAY_TX_FEE = 10000
        base_fee = MIN_TX_FEE

        bytes = self.size()
        min_fee = (1 + (bytes / 1000)) * base_fee

        allow_free = False
        if allow_free:
            # TB TODO Do we care about free transaction area in blocks?
            pass

        # To limit dust spam, require base fee if any output is less than 0.01 
        if min_fee < base_fee:
            for output in self.outputs:
                if output['amount'] < Bitcoin.CENT:
                    min_fee = base_fee
                    break

        if not (min_fee >= 0 and min_fee < Bitcoin.MAX_MONEY):
            min_fee = Bitcoin.MAX_MONEY

        return int(min_fee)

    @staticmethod
    def unserialize(data, as_coinbase=False):
        k = len(data)

        tr = Transaction()
        tr.version = struct.unpack('<L', data[:4])[0]
        num_inputs, data = Bitcoin.unserialize_variable_int(data[4:])
        for i in range(num_inputs):
            txn_input, data = TransactionInput.unserialize(data, as_coinbase=as_coinbase)
            tr.inputs.append(txn_input)

        num_outputs, data = Bitcoin.unserialize_variable_int(data)
        for i in range(num_outputs):
            try:
                txn_output, data = TransactionOutput.unserialize(data)
            except:
                raise
            tr.outputs.append(txn_output)

        tr.lock_time = struct.unpack("<L", data[:4])[0]

        tr.real_size = k - len(data) + 4

        if any(i.signed and (i.signed_hash_type & SIGHASH_ANYONECANPAY) != 0 for i in tr.inputs):
            tr.type = Transaction.TRANSACTION_TYPE_PAYMENT_ANYONECANPAY

        return tr, data[4:]
 
    def as_dict(self):
        t = {
            "hash": ''.join(['{:02x}'.format(v) for v in self.hash()][::-1]),
            "ver": self.version,
            "vin_sz": len(self.inputs),
            "vout_sz": len(self.outputs),
            "size": self.size(),
            "in": [ {
                "prev_out": {
                    "hash": Bitcoin.bytes_to_hexstring(input.tx_hash),
                    "n"   : input.n,
                },
                "scriptSig":
                    ''.join(["{:02x}".format(b) for b in input.scriptSig.serialize()]),
                #"program": [len(x) for x in input.scriptSig.program],
            } for input in self.inputs ],
            "out": [ {
                "value": output.amount,
                "scriptPubKey": 
                    ''.join(["{:02x}".format(b) for b in output.scriptPubKey.serialize()])
            } for output in self.outputs ],
        }

        return t

