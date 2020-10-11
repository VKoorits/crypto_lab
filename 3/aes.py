from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

EXPECTED_KEY_SIZES = [16]
BLOCK_SIZE = 16
IV_SIZE = 16
CTR_IV_BYTE_ORDER = 'big'
SEGMENT_SIZE = 128
AES_MODES = {'ecb', 'cbc', 'cfb', 'ofb', 'ctr'}

def SplitForChunks(data, chunk_size):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def xor(b1, b2): # use xor for bytes
    result = b''
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result

def increase_iv(iv):
    next_iv = int.from_bytes(iv, byteorder=CTR_IV_BYTE_ORDER) + 1
    return next_iv.to_bytes(IV_SIZE,  byteorder=CTR_IV_BYTE_ORDER)

class vkAES:
    def _AesBlockEncrypt(self, block):
        return self.cipher.encrypt(block)

    def _AesBlockDecrypt(self, block):
        return self.cipher.decrypt(block)

    def _ECB_Aes(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            result += self.method(block)
        return result

    def _CBC_AesEncrypt(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)

        result = self.iv
        for block in blocks:
            cipher_input = xor(block, self.iv)
            ciphered_block = self._AesBlockEncrypt(cipher_input)
            result += ciphered_block
            self.iv = ciphered_block
        return result

    def _OFB_AesEncrypt(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)

        result = self.iv
        for block in blocks:
            ciphered_block = self._AesBlockEncrypt(self.iv)
            self.iv = ciphered_block
            result += xor(block, ciphered_block)
        return result

    def _CFB_AesEncrypt(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        
        result = self.iv
        for block in blocks:
            ciphered_block = self._AesBlockEncrypt(self.iv)
            xored_block = xor(block, ciphered_block)
            self.iv = xored_block
            result += xored_block

        return result
    

    def _CTR_Aes(self, data, decrypt=False):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        
        result = b'' if decrypt else self.iv
        for block in blocks:
            ciphered_block = self._AesBlockEncrypt(self.iv)
            xored_block = xor(block, ciphered_block)
            self.iv = increase_iv(self.iv)
            result += xored_block

        return result

    def _CBC_AesDecrypt(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipher_output = self._AesBlockDecrypt(block)
            result += xor(self.iv, cipher_output)
            self.iv = block

        return result

    def _CFB_AesDecrypt(self,data):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipher_output = self._AesBlockEncrypt(self.iv)
            result += xor(block, cipher_output)
            self.iv = block

        return result

    def _OFB_AesDecrypt(self, data):
        blocks = SplitForChunks(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipher_output = self._AesBlockEncrypt(self.iv)
            self.iv = cipher_output
            result += xor(block, cipher_output)

        return result


    def __init__(self, key, mode, iv=None):
        mode = mode.lower()
        if mode not in AES_MODES:
            return None

        self.mode = mode
        self.cipher = AES.new(key, AES.MODE_ECB)
        
        if mode != 'ecb':
            if iv is None:
                return None
            if len(iv) != BLOCK_SIZE:
                return None

        self.iv = iv
    
    def encrypt(self, data):
        if self.mode != 'ctr' and len(data) % BLOCK_SIZE != 0:
            data = pad(data, BLOCK_SIZE)
        
        self.method = self._AesBlockEncrypt
        if self.mode == 'ecb':
            return self._ECB_Aes(data)
        elif self.mode == 'cbc':
            return self._CBC_AesEncrypt(data)
        elif self.mode == 'cfb':
            return self._CFB_AesEncrypt(data)
        elif self.mode == 'ofb':
            return self._OFB_AesEncrypt(data)
        elif self.mode == 'ctr':
            return self._CTR_Aes(data)

    def decrypt(self, data):
        if self.mode != 'ctr' and len(data) % BLOCK_SIZE != 0:
            raise Exception('data size must be a multiple of 16 in length')
        
        self.method = self._AesBlockDecrypt
        if self.mode == 'ecb':
            chipertext = self._ECB_Aes(data)

        self.iv = data[:IV_SIZE]
        data = data[IV_SIZE:]

        if self.mode == 'cbc':
            chipertext = self._CBC_AesDecrypt(data)
        if self.mode == 'cfb':
            chipertext = self._CFB_AesDecrypt(data)
        if self.mode == 'ofb':
            chipertext = self._OFB_AesDecrypt(data)
        if self.mode == 'ctr':
            chipertext = self._CTR_Aes(data, True)
        
        try:
            return unpad(chipertext, BLOCK_SIZE)
        except ValueError:
            return chipertext
