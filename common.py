import addressgen
import ctypes
import struct

VERSION = 3

SPECIAL_SATOSHI = 1
SACRIFICE       = 21000
PIECE_SIZE      = { 1: 20, 2: 119, 3: 119 }

ENCRYPT_NONE   = 0
ENCRYPT_RC4    = 1
ENCRYPT_AES128 = 3
ENCRYPT_AES256 = 4
ENCRYPT_RSA    = 5

RSA_PKCS1_OAEP_PADDING = 4

class RSA:
    def __init__(self, rsa):
        self.rsa = rsa

    def __del__(self):
        addressgen.ssl_library.RSA_free(self.rsa)

    def size(self):
        return addressgen.ssl_library.RSA_size(self.rsa)

def get_random_bytes(b):
    buf = ctypes.create_string_buffer(b)
    ret = addressgen.ssl_library.RAND_bytes(buf, b)
    if ret != 1:
        raise Exception('RNG is bad')
    return buf.raw

def load_public_key(pem):
    pem = pem.encode('ascii')
    buf = ctypes.c_char_p(pem)
    bufio = addressgen.ssl_library.BIO_new_mem_buf(buf, len(pem))

    rsa = addressgen.ssl_library.PEM_read_bio_RSA_PUBKEY(bufio, None, 0, None)

    addressgen.ssl_library.BIO_free(bufio)

    return RSA(rsa)

def load_private_key(pem):
    pem = pem.encode('ascii')
    buf = ctypes.c_char_p(pem)
    bufio = addressgen.ssl_library.BIO_new_mem_buf(buf, len(pem))

    rsa = addressgen.ssl_library.PEM_read_bio_RSAPrivateKey(bufio, None, 0, None)

    addressgen.ssl_library.BIO_free(bufio)

    return RSA(rsa)

def encrypt(key, message, algorithm, iv=None):
    if algorithm == ENCRYPT_NONE:
        return message
    elif algorithm == ENCRYPT_RC4: # RC4, symmetric key
        ctx = ctypes.create_string_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        cipher = addressgen.ssl_library.EVP_rc4()
        key_length = len(key)

        # configure parameters
        r = addressgen.ssl_library.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
        if r == 0:
            raise Exception("EncryptInit failed")
        addressgen.ssl_library.EVP_CIPHER_CTX_set_key_length(ctx, key_length)

        iv = ctypes.create_string_buffer(b'\x00' * 16);
        r = addressgen.ssl_library.EVP_EncryptInit_ex(ctx, None, None, ctypes.c_char_p(key), iv)
        if r == 0:
            raise Exception("EncryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_padding(ctx, 1)

        block_size = addressgen.ssl_library.EVP_CIPHER_block_size(cipher)

        outlen = ctypes.c_int(len(message) + block_size)
        out = ctypes.create_string_buffer(outlen.value)

        r = addressgen.ssl_library.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), ctypes.c_char_p(message), len(message))
        if r == 0:
            raise Exception("EncryptUpdate failed")

        outlen2 = ctypes.c_int(block_size)
        out2 = ctypes.create_string_buffer(outlen2.value)
        r = addressgen.ssl_library.EVP_EncryptFinal_ex(ctx, out2, ctypes.byref(outlen2))
        if r == 0:
            raise Exception("EncryptFinal failed")

        ret = out[:outlen.value] + out2[:outlen2.value]
        addressgen.ssl_library.EVP_CIPHER_CTX_cleanup(ctx)
        return ret
    elif algorithm == ENCRYPT_AES128 or algorithm == ENCRYPT_AES256:
        ctx = ctypes.create_string_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        key_length = len(key)

        if algorithm == ENCRYPT_AES128:
            cipher = addressgen.ssl_library.EVP_aes_128_cbc()
            assert key_length == 16
        else:
            cipher = addressgen.ssl_library.EVP_aes_256_cbc()
            assert key_length == 32

        # configure parameters
        r = addressgen.ssl_library.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
        if r == 0:
            raise Exception("EncryptInit failed")
        addressgen.ssl_library.EVP_CIPHER_CTX_set_key_length(ctx, key_length)

        assert iv is not None and len(iv) == key_length
        iv = ctypes.create_string_buffer(iv)
        r = addressgen.ssl_library.EVP_EncryptInit_ex(ctx, None, None, ctypes.c_char_p(key), iv)
        if r == 0:
            raise Exception("EncryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_padding(ctx, 1)

        block_size = addressgen.ssl_library.EVP_CIPHER_block_size(cipher)

        outlen = ctypes.c_int(len(message) + block_size)
        out = ctypes.create_string_buffer(outlen.value)

        r = addressgen.ssl_library.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), ctypes.c_char_p(message), len(message))
        if r == 0:
            raise Exception("EncryptUpdate failed")

        outlen2 = ctypes.c_int(block_size)
        out2 = ctypes.create_string_buffer(outlen2.value)
        r = addressgen.ssl_library.EVP_EncryptFinal_ex(ctx, out2, ctypes.byref(outlen2))
        if r == 0:
            raise Exception("EncryptFinal failed")

        ret = out[:outlen.value] + out2[:outlen2.value]
        addressgen.ssl_library.EVP_CIPHER_CTX_cleanup(ctx)
        return ret
    elif algorithm == ENCRYPT_RSA:
        rsa_size = addressgen.ssl_library.RSA_size(key.rsa)
        buf      = ctypes.create_string_buffer(rsa_size)

        # flen must be ... less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING
        if len(message) > (rsa_size - 41):
            raise Exception("RSA can only encrypt messages less than the key size")

        encrypt_len = addressgen.ssl_library.RSA_public_encrypt(len(message), ctypes.c_char_p(message), buf, key.rsa, RSA_PKCS1_OAEP_PADDING)
        if encrypt_len == -1:
            raise Exception("RSA encryption failed")

        return buf.raw
    else:
        # TODO - someone please implement me!
        raise Exception("unknown encryption algorithm {}".format(algorithm))

def decrypt(key, message, algorithm, iv=None):
    if algorithm == ENCRYPT_NONE:
        return message
    elif algorithm == ENCRYPT_RC4:
        ctx = ctypes.create_unicode_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        key_length = len(key)
        cipher = addressgen.ssl_library.EVP_rc4()

        # First configure parameters
        r = addressgen.ssl_library.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
        if r == 0:
            raise Exception("EncryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_key_length(ctx, key_length)

        # Then reinit..
        iv = ctypes.create_string_buffer(b'\x00' * 16);
        r = addressgen.ssl_library.EVP_DecryptInit_ex(ctx, None, None, ctypes.c_char_p(key), iv)
        if r == 0:
            raise Exception("DecryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_padding(ctx, 1)

        block_size = addressgen.ssl_library.EVP_CIPHER_block_size(cipher)

        outlen = ctypes.c_int(len(message) + block_size)
        out = ctypes.create_string_buffer(b'\x00' * outlen.value)

        r = addressgen.ssl_library.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), ctypes.c_char_p(message), len(message))
        if r == 0:
            raise Exception("DecryptUpdate failed")

        out2 = ctypes.create_string_buffer(b'\x00' * block_size)
        outlen2 = ctypes.c_int(block_size)
        r = addressgen.ssl_library.EVP_DecryptFinal_ex(ctx, out2, ctypes.byref(outlen2))

        addressgen.ssl_library.EVP_CIPHER_CTX_cleanup(ctx)
        return out[:outlen.value] + out2[:outlen2.value]
    elif algorithm == ENCRYPT_AES128 or algorithm == ENCRYPT_AES256:
        ctx = ctypes.create_unicode_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        key_length = len(key)
        if algorithm == ENCRYPT_AES128:
            cipher = addressgen.ssl_library.EVP_aes_128_cbc()
            assert key_length == 16
        else:
            cipher = addressgen.ssl_library.EVP_aes_256_cbc()
            assert key_length == 32

        # First configure parameters
        r = addressgen.ssl_library.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
        if r == 0:
            raise Exception("EncryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_key_length(ctx, key_length)

        # Then reinit..
        assert iv is not None and len(iv) == key_length
        iv = ctypes.create_string_buffer(iv)
        r = addressgen.ssl_library.EVP_DecryptInit_ex(ctx, None, None, ctypes.c_char_p(key), iv)
        if r == 0:
            raise Exception("DecryptInit failed")

        addressgen.ssl_library.EVP_CIPHER_CTX_set_padding(ctx, 1)

        block_size = addressgen.ssl_library.EVP_CIPHER_block_size(cipher)

        outlen = ctypes.c_int(len(message) + block_size)
        out = ctypes.create_string_buffer(b'\x00' * outlen.value)

        r = addressgen.ssl_library.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), ctypes.c_char_p(message), len(message))
        if r == 0:
            raise Exception("DecryptUpdate failed")

        out2 = ctypes.create_string_buffer(b'\x00' * block_size)
        outlen2 = ctypes.c_int(block_size)
        r = addressgen.ssl_library.EVP_DecryptFinal_ex(ctx, out2, ctypes.byref(outlen2))

        addressgen.ssl_library.EVP_CIPHER_CTX_cleanup(ctx)
        return out[:outlen.value] + out2[:outlen2.value]
    elif algorithm == ENCRYPT_RSA:
        rsa_size = addressgen.ssl_library.RSA_size(key.rsa)
        buf      = ctypes.create_string_buffer(rsa_size)

        ## flen must be ... less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING
        #if len(message) > (rsa_size - 41):
        #    raise Exception("RSA can only encrypt messages less than the key size")

        decrypt_len = addressgen.ssl_library.RSA_private_decrypt(len(message), ctypes.c_char_p(message), buf, key.rsa, RSA_PKCS1_OAEP_PADDING)
        if decrypt_len == -1:
            raise Exception("RSA encryption failed")

        return buf[:decrypt_len]

