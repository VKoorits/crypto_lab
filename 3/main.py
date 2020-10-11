
from aes import vkAES, BLOCK_SIZE, SEGMENT_SIZE
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad


def check_vkAES():
    key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
    value = bytes.fromhex('0000000100020003000400050006000700080009000a000b000c000d000e000f0001000200030004')
    iv = bytes.fromhex('69dda8455c7dd4254bf353b773304eed')

    cipher = AES.new(key, AES.MODE_ECB)
    e = cipher.encrypt(pad(value, BLOCK_SIZE))

    cipher =  vkAES(key, "ECB")
    e_my = cipher.encrypt(value)
    d_my = cipher.decrypt(e_my)
    print('ECB: {} : {}'.format(e==e_my, d_my==value))
    
    # --

    cipher = AES.new(key, AES.MODE_CBC, iv)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))


    cipher =  vkAES(key, "CBC", iv)
    e_my = cipher.encrypt(value)
    cipher =  vkAES(key, "CBC", iv)
    d_my = cipher.decrypt(e_my)
    print('CBC: {} : {}'.format(e==e_my, d_my==value))

    # --

    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=SEGMENT_SIZE)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))

    cipher =  vkAES(key, "CFB", iv)
    e_my = cipher.encrypt(value)
    cipher =  vkAES(key, "CFB", iv)
    d_my = cipher.decrypt(e_my)
    print('CFB: {} : {}'.format(e==e_my, d_my==value))

    # --

    cipher = AES.new(key, AES.MODE_OFB, iv)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))

    cipher =  vkAES(key, "OFB", iv)
    e_my = cipher.encrypt(value)
    cipher =  vkAES(key, "OFB", iv)
    d_my = cipher.decrypt(e_my)
    print('OFB: {} : {}'.format(e==e_my, d_my==value))

    # --
    counter=Counter.new(128, initial_value=int(iv.hex(), 16))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    e = iv + cipher.encrypt(value)

    cipher =  vkAES(key, "CTR", iv)
    e_my = cipher.encrypt(value)
    cipher =  vkAES(key, "CTR", iv)
    d_my = cipher.decrypt(e_my)

    print('CTR: {} : {}'.format(e==e_my, d_my==value))


def task_3():
    key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
    ciphertext = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    cipher =  vkAES(key, "CBC")
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext) # b'Basic CBC mode encryption needs padding.\x08\x08\x08\x08\x08\x08\x08\x08'


    key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
    ciphertext = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
    cipher =  vkAES(key, "CBC")
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext) # b'Our implementation uses rand. IV\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

    key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
    ciphertext = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    cipher =  vkAES(key, "CTR")
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext) # b'CTR mode lets you build a stream cipher from a block cipher.'

    key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
    ciphertext = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    cipher =  vkAES(key, "CTR")
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext) # b'Always avoid the two time pad!'


check_vkAES()
task_3()