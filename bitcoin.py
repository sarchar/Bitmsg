import hashlib
import string
import struct
import time

import base58

class InvalidNetworkMagic(Exception):
    pass

class InvalidCommandEncoding(Exception):
    pass

class MessageChecksumFailure(Exception):
    pass

class MessageTooShort(Exception):
    pass

class Bitcoin:
    NETWORK_DELIVERY = 1
    NETWORK_MAGIC    = bytes([0xF9, 0xBE, 0xB4, 0xD9]) 

    @staticmethod
    def format_money(value):
        assert isinstance(value, int)
        neg = ''
        if value < 0:
            neg = '-'
            value *= -1
        dec = value % 100000000
        return neg + str(int(value/100000000)) + ('.{:08}'.format(dec).rstrip('0') if dec != 0 else '')

    @staticmethod
    def parse_money(amount_string):
        # Replace commas
        amount_string = amount_string.strip().replace(',','')

        # If the number starts with a '-' we need to remember that
        neg = 1
        if len(amount_string) and amount_string[0] == '-':
            neg = -1
            amount_string = amount_string[1:]

        # The rest of the number can only be 0..9 and a period
        assert len(set(amount_string).difference(set(string.digits + "."))) == 0

        # Handle case when zero or empty string is passed in
        amount_string = amount_string.lstrip('0')
        if len(amount_string) == 0: 
            return 0

        # Find the first '.', and if there are more then int() will raise a ValueError
        i = amount_string.find('.')
        scale = 100000000

        if i < 0:
            # No '.' found, use it as a whole number
            v = int(amount_string) * scale
        elif i == len(amount_string) - 1:
            # The '.' was the last char in the string, ignore it
            amount_string = amount_string[:-1]
            if len(amount_string) == 0:
                v = 0
            else:
                v = int(amount_string) * scale
        else:
            # Cannot pass two decimals
            decimal_string = amount_string[i+1:].rstrip('0')
            assert '.' not in decimal_string

            num_decimal = len(decimal_string)  # number of decimals present (trailing 0s have already been removed)
            scale = scale // (10 ** num_decimal) #stick with integer division
            amount_string = amount_string[:i] + decimal_string
            if len(amount_string) == 0:
                v = 0
            else:
                v = int(amount_string, 10) * scale

        return neg * v

    @staticmethod
    def hash(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.sha256()
        hasher2.update(hasher.digest())
        return hasher2.digest()

    @staticmethod
    def bytes_to_hexstring(data, reverse=True):
        if reverse:
            return ''.join(reversed(['{:02x}'.format(v) for v in data]))
        else:
            return ''.join(['{:02x}'.format(v) for v in data])

    @staticmethod
    def hexstring_to_bytes(s, reverse=True):
        if reverse:
            return bytes(reversed([int(s[x:x+2], 16) for x in range(0, len(s), 2)]))
        else:
            return bytes([int(s[x:x+2], 16) for x in range(0, len(s), 2)])

    @staticmethod
    def wrap_message(command, payload, delivery_type=NETWORK_DELIVERY):
        if delivery_type == Bitcoin.NETWORK_DELIVERY:
            magic = Bitcoin.NETWORK_MAGIC
            command = command[:12].encode("ascii")
            command += bytes([0] * (12 - len(command))) # pad to 12 bytes
            length = struct.pack("<L", len(payload))
            checksum = Bitcoin.hash(payload)[:4] # Checksum is first 4 bytes
            return magic + command + length + checksum + payload
        else:
            raise Exception("Unknown delivery type {}".format(delivery_type))

    @staticmethod
    def unwrap_message(data, delivery_type=NETWORK_DELIVERY):
        if delivery_type == Bitcoin.NETWORK_DELIVERY:
            if len(data) < 24:
                return None, None, data

            magic = data[:4]
            if magic != Bitcoin.NETWORK_MAGIC:
                print(Bitcoin.bytes_to_hexstring(magic, reverse=False))
                raise InvalidNetworkMagic()

            i = 0
            while data[4+i] != 0 and i < 12:
                i += 1

            try:
                command = data[4:4+i].decode('ascii')
            except UnicodeDecodeError:
                raise InvalidCommandEncoding()

            length   = struct.unpack("<L", data[16:20])[0]
            checksum = data[20:24]

            if (len(data) - 24) < length:
                return None, None, data
            
            payload = data[24:24+length]
            leftover = data[24+length:]

            hash = Bitcoin.hash(payload)
            if hash[:4] != checksum:
                raise MessageChecksumFailure()

            return command, payload, leftover
        else:
            raise Exception("Unknown delivery type {}".format(delivery_type))


    @staticmethod
    def serialize_string(s):
        s = s.encode('utf8')
        length = Bitcoin.serialize_variable_int(len(s))
        return length + s

    @staticmethod
    def unserialize_string(data):
        length, data = Bitcoin.unserialize_variable_int(data)
        s = data[:length].decode("utf8")
        return s, data[length:]

    @staticmethod
    def serialize_inv(msg, hash):
        return struct.pack("<L", msg) + hash

    @staticmethod
    def unserialize_inv(data):
        if len(data) < 36:
            raise MessageTooShort()

        type = struct.unpack("<L", data[:4])[0]
        return {'type': type, 'hash': data[4:36]}, data[36:]

    @staticmethod
    def serialize_variable_int(i):
        if i < 0xfd:
            return struct.pack("B", i)
        if i <= 0xffff:
            return struct.pack("<BH", 0xfd, i)
        if i <= 0xffffffff:
            return struct.pack("<BL", 0xfe, i)
        return struct.pack("<BQ", 0xff, i)

    @staticmethod
    def unserialize_variable_int(data):
        if len(data) == 0:
            raise MessageTooShort()
        i = data[0]
        if i < 0xfd:
            return i, data[1:]
        elif i == 0xfd:
            if len(data) < 3:
                raise MessageTooShort()
            return struct.unpack("<H", data[1:3])[0], data[3:]
        elif i == 0xfe:
            if len(data) < 5:
                raise MessageTooShort()
            return struct.unpack("<L", data[1:5])[0], data[5:]
        else:
            if len(data) < 9:
                raise MessageTooShort()
            return struct.unpack("<Q", data[1:9])[0], data[9:]


    @staticmethod
    def serialize_variable_int_size(i):
        if i < 0xfd:
            return 1
        if i <= 0xffff:
            return 3
        if i <= 0xffffffff:
            return 5
        return 9

    @staticmethod
    def serialize_network_address(pa, services, with_timestamp=True):
        if pa is not None:
            quads   = pa[0].split(".")
            address = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, int(quads[0]), int(quads[1]), int(quads[2]), int(quads[3])])
            port    = struct.pack(">H", pa[1])
        else:
            address = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0])
            port    = bytes([0, 0])

        if with_timestamp:
            return struct.pack("<LQ", int(time.time()), services) + address + port
        else:
            return struct.pack("<Q", services) + address + port

    @staticmethod
    def unserialize_network_address(data, with_timestamp=True):
        if with_timestamp and len(data) < 30:
            raise MessageTooShort()
        elif not with_timestamp and len(data) < 26:
            raise MessageTooShort()

        if with_timestamp:
            when, services = struct.unpack("<LQ", data[:12])
            data = data[12:]
        else:
            services = struct.unpack("<Q", data[:8])[0]
            data = data[8:]

        address = data[:16]
        port = struct.unpack(">H", data[16:18])[0]

        if address[0:-4] == bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]):
            address = '.'.join('{}'.format(v) for v in address[-4:])

        data = data[18:]

        if with_timestamp:
            return ((address, port), services, when, data)
        else:
            return ((address, port), services, data)


Bitcoin.COIN = Bitcoin.parse_money( "1.0" )
Bitcoin.CENT = Bitcoin.parse_money( "0.01" )
Bitcoin.MAX_MONEY = 21000000 * Bitcoin.COIN 


