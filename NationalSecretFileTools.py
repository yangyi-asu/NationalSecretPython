#!/usr/bin/python
# -*-coding: utf-8-*-
# @Time           : 2021/4/26 9:57
# @Author         : yannic
# @File           : NationalSecretTools.py
# @Software       : PyCharm

import lz4.frame
import lz4.block
from lz4.frame import compress, decompress
import hashlib
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


class SM4:
    """
     国密sm4加解密算法工具类
    """

    def __init__(self):
        self.crypt_sm4 = CryptSM4()

    def encrypt(self, encrypt_key, value):
        """
        国密sm4加密
        :param encrypt_key: sm4加密key
        :param value: 待加密的字符串
        :return: sm4加密后的hex值
        """
        crypt_sm4 = self.crypt_sm4
        bf = bytes.fromhex(encrypt_key)
        crypt_sm4.set_key(bf, SM4_ENCRYPT)

        encrypt_value = crypt_sm4.crypt_ecb(value)  # bytes类型
        return encrypt_value

    def decrypt(self, decrypt_key, encrypt_value):
        """
        国密sm4解密
        :param decrypt_key:sm4加密key
        :param encrypt_value: 待解密的hex值
        :return: 原字符串
        """
        crypt_sm4 = self.crypt_sm4
        bf = bytes.fromhex(decrypt_key)
        crypt_sm4.set_key(bf, SM4_DECRYPT)
        decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)  # bytes类型
        return decrypt_value


class Sm4FileEncryptUtil:
    """
    Sm4文件加解密工具类
    """
    sm4 = SM4()

    def __init__(self, **kwargs):
        if 'secret' in kwargs:
            self.secret = kwargs['secret']

    def encrypt_file(self, src_file, out_file):
        """
        获取文件的sm4加密文件
        """
        try:
            with open(out_file, 'wb') as out:
                with open(src_file, 'rb') as in_file:
                    out.write(self.sm4.encrypt(self.secret, in_file.read()))
                out.flush()
                out.close()
        except IOError as err:
            print('文件处理异常', err)

    def decrypt_file(self, src_file, out_file):
        try:
            with open(out_file, 'wb') as out:
                with open(src_file, mode='rb') as inFile:
                    out.write(self.sm4.decrypt(self.secret, inFile.read()))
                out.flush()
                out.close()
        except IOError as err:
            print('文件处理异常', err)


class Sm3FileHashUtil:
    """
    文件HASH值sm3算法的实现
    """

    @staticmethod
    def get_file_sm3_hash(file):
        """
        获取文件的sm3值
        """
        m = hashlib.new('sm3')
        with open(file, 'rb') as f:
            for line in f:
                m.update(line)
        sm3code = m.hexdigest()
        return sm3code


class Lz4Util:
    """
    Lz4算法的文件解压缩
    """

    @staticmethod
    def compress_file(src_file, out_file):
        """
        压缩文件
        """
        try:
            with open(out_file, 'wb') as out:
                with open(src_file, 'rb') as inFile:
                    out.write(compress(inFile.read()))
                out.flush()
                out.close()
        except IOError as err:
            print('文件处理异常', err)

    @staticmethod
    def decompress_file(src_file, out_file):
        """
        解压文件
        """
        try:
            with open(out_file, 'wb') as out:
                with lz4.frame.open(src_file, mode='rb') as in_file:
                    out.write(in_file.read())
                out.flush()
                out.close()
        except IOError as err:
            print('文件处理异常', err)


if __name__ == '__main__':
    """ 文件Lz4压缩算法 """
    Lz4Util.compress_file('hello.txt', 'compress_hello.lz4')
    Lz4Util.decompress_file('compress_hello.lz4', 'ecompres_hello.txt')
    """  文件SM3国密hash文件 """
    hash_str = Sm3FileHashUtil.get_file_sm3_hash('hello.txt')
    print(hash_str)
    """  文件SM4加解密  """
    sm4_tools = Sm4FileEncryptUtil(secret='5a7d371e8ef22fc887504b3881499175')
    sm4_tools.encrypt_file('hello.txt', 'hello.sm4')
    sm4_tools.decrypt_file('hello.sm4', 'decrypt_hello.txt')

