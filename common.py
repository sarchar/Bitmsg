import addressgen
import ctypes

VERSION = 2

SPECIAL_SATOSHI = 1
SACRIFICE       = 21000
PIECE_SIZE      = { 1: 20, 2: 119 }

ENCRYPT_NONE   = 0
ENCRYPT_RC4    = 1
ENCRYPT_ECDSA  = 2
ENCRYPT_AES128 = 3

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
    elif algorithm == ENCRYPT_AES128:
        ctx = ctypes.create_string_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        cipher = addressgen.ssl_library.EVP_aes_128_cbc()
        key_length = len(key)
        assert key_length == 16

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
    elif algorithm == ENCRYPT_AES128:
        ctx = ctypes.create_unicode_buffer(140)
        addressgen.ssl_library.EVP_CIPHER_CTX_init(ctx)

        cipher = addressgen.ssl_library.EVP_aes_128_cbc()
        key_length = len(key)
        assert key_length == 16

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

