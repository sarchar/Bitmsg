#!/usr/bin/env python
import ctypes
import hashlib
from base58 import encode as base58_encode

################################################################################
################################################################################
ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
NID_secp160k1 = 708
NID_secp256k1 = 714

def gen_ecdsa_pair():
    k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)

    if ssl_library.EC_KEY_generate_key(k) != 1:
        raise Exception("internal error?")

    bignum_private_key = ssl_library.EC_KEY_get0_private_key(k)
    size = (ssl_library.BN_num_bits(bignum_private_key)+7)//8
    storage = ctypes.create_string_buffer(size)
    ssl_library.BN_bn2bin(bignum_private_key, storage)
    private_key = storage.raw

    size = ssl_library.i2o_ECPublicKey(k, 0)
    storage = ctypes.create_string_buffer(size)
    pstorage = ctypes.pointer(storage)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
    public_key = storage.raw

    ssl_library.EC_KEY_free(k)
    return public_key, private_key

def get_public_key(private_key):
    k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
    
    storage = ctypes.create_string_buffer(private_key)
    bignum_private_key = ssl_library.BN_new()
    ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

    group = ssl_library.EC_KEY_get0_group(k)
    point = ssl_library.EC_POINT_new(group)

    ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
    ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
    ssl_library.EC_KEY_set_public_key(k, point)

    size = ssl_library.i2o_ECPublicKey(k, 0)
    storage = ctypes.create_string_buffer(size)
    pstorage = ctypes.pointer(storage)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
    public_key = storage.raw

    ssl_library.EC_POINT_free(point)
    ssl_library.BN_free(bignum_private_key)
    ssl_library.EC_KEY_free(k)
    return public_key

def generate_address(public_key, version=0):
    assert isinstance(public_key, bytes)

    if public_key[0] in (0x04, 0x03, 0x02):
        s = public_key
    else:
        raise Exception("Unhandled ECDSA public key? type={}".format(public_key[0]))
    
    return generate_address_from_data(s, version=version)

def generate_address_from_data(data, version=0):
    assert isinstance(data, bytes)
    hasher = hashlib.sha256()
    hasher.update(data)
    r = hasher.digest()

    hasher = hashlib.new('ripemd160')
    hasher.update(r)
    r = hasher.digest()

    a = base58_check(r, version=version)

    if version == 0:
        # Since '1' is a zero byte in base58, it won't be present in the output address.
        i = 0
        while r[i] == 0: 
            i += 1

        return '1' + ('1' * i) + a

    return a

def base58_check(src, version=0):
    src = bytes([version]) + src
    hasher = hashlib.sha256()
    hasher.update(src)
    r = hasher.digest()

    hasher = hashlib.sha256()
    hasher.update(r)
    r = hasher.digest()

    checksum = r[:4]
    s = src + checksum

    return base58_encode(int.from_bytes(s, 'big'))

def ecdsa_sign(private_key, hash):
    k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
    
    storage = ctypes.create_string_buffer(private_key)
    bignum_private_key = ssl_library.BN_new()
    ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

    group = ssl_library.EC_KEY_get0_group(k)
    point = ssl_library.EC_POINT_new(group)

    ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
    ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
    ssl_library.EC_KEY_set_public_key(k, point)

    assert isinstance(hash, bytes)
    dgst = ctypes.cast((ctypes.c_ubyte*len(hash))(*[int(x) for x in hash]), ctypes.POINTER(ctypes.c_ubyte))

    siglen = ctypes.c_int(ssl_library.ECDSA_size(k))
    signature = ctypes.create_string_buffer(siglen.value)
    if ssl_library.ECDSA_sign(0, dgst, len(hash), signature, ctypes.byref(siglen), k) == 0:
        raise Exception("Failed to sign signature")

    signature = signature.raw[:siglen.value]

    ssl_library.EC_POINT_free(point)
    ssl_library.BN_free(bignum_private_key)
    ssl_library.EC_KEY_free(k)

    return signature

def test():
    public_key, private_key = gen_ecdsa_pair()

    hex_private_key = ''.join(["{:02x}".format(i) for i in private_key])
    assert len(hex_private_key) == 64

    print("ECDSA private key (random number / secret exponent) = {}".format(hex_private_key))
    print("ECDSA public key = {}".format(''.join(['{:02x}'.format(i) for i in public_key])))
    bitcoin_private_key = base58_check(private_key, version=128)
    print("Bitcoin private key (Base58Check) = {}, len={}".format(bitcoin_private_key, len(bitcoin_private_key)))

    addr = generate_address(public_key)
    print("Bitcoin 1-Address: {} (length={})".format(addr, len(addr)))

    addr = generate_address(public_key, version=5)
    print("Bitcoin 3-Address: {} (length={})".format(addr, len(addr)))

    hasher = hashlib.md5()
    hasher.update('Hello, world!'.encode('ascii'))
    hash = hasher.digest()
    print("Signature of MD5SUM('Hello, world!'): {}".format(''.join(['{:02x}'.format(i) for i in ecdsa_sign(private_key, hash)])))

if __name__ == "__main__":
    test()

