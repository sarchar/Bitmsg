""" base58 encoding / decoding functions """
 
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base_count = len(alphabet)
        
def encode(num):
    """ Returns num in a base58-encoded string """
    encode = ''
    
    if (num < 0):
        return ''
    
    while (num >= base_count):    
        mod = num % base_count
        encode = alphabet[mod] + encode
        num = num // base_count
 
    if (num):
        encode = alphabet[num] + encode
 
    return encode
 
def decode(s):
    """ Decodes the base58-encoded string s into an integer """
    decoded = 0
    multi = 1
    s = s[::-1]
    for char in s:
        decoded += multi * alphabet.index(char)
        multi = multi * base_count
        
    return decoded

def decode_to_bytes(s):
    v = decode(s)

    result = b''
    while v >= 256:
        div, mod = divmod(v, 256)
        result = bytes([mod]) + result
        v = div
    result = bytes([v]) + result

    i = 0
    while i < len(s) and s[i] == '1':
        i += 1

    result = (b'\x00' * i) + result

    return result

def encode_from_bytes(v):
    i = 0
    while v[i] == 0:
        i += 1
    n = int.from_bytes(v[i:], 'big')
    return ('1' * i) + encode(n)

