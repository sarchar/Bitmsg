from bitcoin import Bitcoin

OP_0 = 0

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5a
OP_11 = 0x5b
OP_12 = 0x5c
OP_13 = 0x5d
OP_14 = 0x5e
OP_15 = 0x5f
OP_16 = 0x60

OP_VERIFY      = 0x69
OP_RETURN      = 0x6a

OP_DUP         = 0x76
OP_EQUALVERIFY = 0x88
OP_HASH160     = 0xa9
OP_CHECKSIG    = 0xac

OP_CHECKMULTISIG = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf

OPCODE_MAP = {
    OP_0                   : "OP_0",
    OP_PUSHDATA1           : "OP_PUSHDATA1",
    OP_PUSHDATA2           : "OP_PUSHDATA2",
    OP_PUSHDATA4           : "OP_PUSHDATA4",
    OP_1                   : "OP_1",
    OP_2                   : "OP_2",
    OP_3                   : "OP_3",
    OP_4                   : "OP_4",
    OP_5                   : "OP_5",
    OP_6                   : "OP_6",
    OP_7                   : "OP_7",
    OP_8                   : "OP_8",
    OP_9                   : "OP_9",
    OP_10                  : "OP_10",
    OP_11                  : "OP_11",
    OP_12                  : "OP_12",
    OP_13                  : "OP_13",
    OP_14                  : "OP_14",
    OP_15                  : "OP_15",
    OP_16                  : "OP_16",
    OP_VERIFY              : "OP_VERIFY",
    OP_RETURN              : "OP_RETURN",
    OP_DUP                 : "OP_DUP",
    OP_EQUALVERIFY         : "OP_EQUALVERIFY",
    OP_HASH160             : "OP_HASH160",
    OP_CHECKSIG            : "OP_CHECKSIG",
    OP_CHECKMULTISIG       : "OP_CHECKMULTISIG",
    OP_CHECKMULTISIGVERIFY : "OP_CHECKMULTISIGVERIFY",
}

OPCODE_NAMES = dict((y,x) for x,y in OPCODE_MAP.items())

class Script:
    # TODO - lots of stuff. This module is only skeleton enough
    # to parse the most basic of transactions.

    def __init__(self):
        self.clear()

    def clear(self):
        self.program = []
        self.ip = 0

    def pushOp(self, opcode):
        #TODO - assert opcode is valid
        self.program.append(bytes([opcode]))

    def pushData(self, b):
        assert isinstance(b, bytes)

        if len(b) < int(OP_PUSHDATA1):
            self.program.append(bytes([len(b)]))
        elif len(b) <= 0xff:
            self.program.append(bytes([OP_PUSHDATA1, len(b)]))
        elif len(b) <= 0xffff:
            self.program.append(bytes([OP_PUSHDATA2, len(b) & 0xff, (len(b) >> 8) & 0xff]))
        else:
            self.program.append(bytes([OP_PUSHDATA4, len(b) & 0xff, (len(b) >> 8) & 0xff, (len(b) >> 16) & 0xff, (len(b) >> 24) & 0xff]))
        
        self.program.append(b)

    def serialize(self):
        return b''.join(self.program)

    def serialize_size(self):
        return sum(len(v) for v in self.program)

    @staticmethod
    def unserialize(data, program_size, as_coinbase=False):
        s = Script()
        s.program = []

        if as_coinbase:
            s.program.append(data[:program_size])
        else:
            p = 0
            while p < program_size:
                c = data[p]
                if c < int(OP_PUSHDATA1):
                    p += 1
                    s.pushData(data[p:p+c])
                    #print('OP_PUSHDATA1', c, Bitcoin.bytes_to_hexstring(data[p:p+c], reverse=False))
                    p += c
                elif c == int(OP_PUSHDATA1):
                    p += 2
                    c = data[p-1]
                    s.pushData(data[p:p+c])
                    #print('OP_PUSHDATA2', c, Bitcoin.bytes_to_hexstring(data[p:p+c], reverse=False))
                    p += c
                elif c == int(OP_PUSHDATA2):
                    p += 3
                    c = data[p-2] | (data[p-1] << 8)
                    s.pushData(data[p:p+c])
                    #print('OP_PUSHDATA3', c, Bitcoin.bytes_to_hexstring(data[p:p+c], reverse=False))
                    p += c
                elif c == int(OP_PUSHDATA4):
                    p += 5
                    c = data[p-4] | (data[p-3] << 8) | (data[p-2] << 16) | (data[p-1] << 24)
                    s.pushData(data[p:p+c])
                    #print('OP_PUSHDATA3', c, Bitcoin.bytes_to_hexstring(data[p:p+c], reverse=False))
                    p += c
                else:
                    p += 1
                    s.pushOp(c)
                    #print('push op', c)

            assert p == program_size

        assert s.serialize() == data[:program_size]
        return s, data[program_size:]
    
    def parse(self, s):
        ops = s.split()

        for op in ops:
            op = op.strip()

            if op in OPCODE_NAMES:
                self.pushOp(OPCODE_NAMES[op])
            else:
                self.pushData(bytes([int(op[x:x+2], 16) for x in range(0, len(op), 2)]))


