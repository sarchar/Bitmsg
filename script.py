from bitcoin import Bitcoin

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

OP_RETURN      = 0x6a

OP_DUP         = 0x76
OP_EQUALVERIFY = 0x88
OP_HASH160     = 0xa9
OP_CHECKSIG    = 0xac

OPCODE_MAP = {
    OP_PUSHDATA1  : "OP_PUSHDATA1",
    OP_PUSHDATA2  : "OP_PUSHDATA2",
    OP_PUSHDATA4  : "OP_PUSHDATA4",
    OP_RETURN     : "OP_RETURN",
    OP_DUP        : "OP_DUP",
    OP_EQUALVERIFY: "OP_EQUALVERIFY",
    OP_HASH160    : "OP_HASH160",
    OP_CHECKSIG   : "OP_CHECKSIG",
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


