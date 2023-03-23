#aes encryption and decryption tool

import sys
import os
import argparse
import base64
import hashlib
import getpass
from Crypto.Cipher import AES
from Crypto import Random

#define the input and output formats
input_formats = ['base64', 'hex', 'raw']
output_formats = ['base64', 'hex', 'raw']

#generate a secret key from a password
def generate_key(password, salt, key_size):
    return hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=key_size)

#generate a random salt
def generate_salt():
    return Random.new().read(16)

#pad the input string so that its length is a multiple of 16
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

#unpad the input string
def unpad(s):
    return s.rstrip(b"\0")

#encrypt the input string
def encrypt(raw, password, input_format, output_format, key_size):
    raw = pad(raw)
    salt = generate_salt()
    key = generate_key(password, salt, key_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(raw)
    if output_format == 'base64':
        return base64.b64encode(salt + iv + enc)
    elif output_format == 'hex':
        return (salt + iv + enc).encode('hex')
    elif output_format == 'raw':
        return salt + iv + enc
    
#decrypt the input string
def decrypt(enc, password, input_format, output_format, key_size):
    if input_format == 'base64':
        enc = base64.b64decode(enc)
    elif input_format == 'hex':
        enc = enc.decode('hex')
    salt = enc[:16]
    iv = enc[16:32]
    key = generate_key(password, salt, key_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(enc[32:]))
    if output_format == 'base64':
        return base64.b64encode(dec)
    elif output_format == 'hex':
        return dec.encode('hex')
    elif output_format == 'raw':
        return dec
    
 # encrypt the input file
def encrypt_file(file_path, password, output_format, key_size):
    with open(file_path, 'rb') as f:
        raw = f.read()
    encrypted_data = encrypt(raw, password, 'raw', output_format, key_size)
    return encrypted_data

# decrypt the input file
def decrypt_file(file_path, password, input_format, key_size):
    with open(file_path, 'rb') as f:
        enc = f.read()
    decrypted_data = decrypt(enc, password, input_format, 'raw', key_size)
    return decrypted_data
    
#main function
def main():
    #parse the command line arguments
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a string using AES')
    parser.add_argument('-e', '--encrypt', help='encrypt the input string', action='store_true')
    parser.add_argument('-d', '--decrypt', help='decrypt the input string', action='store_true')
    parser.add_argument('-i', '--input', help='input string', required=True)
    parser.add_argument('-p', '--password', help='password')
    parser.add_argument('-if', '--input-format', help='input format', choices=input_formats, default='raw')
    parser.add_argument('-of', '--output-format', help='output format', choices=output_formats, default='raw')
    parser.add_argument('-k', '--key-size', help='key size', type=int, default=32)
    parser.add_argument('-ef', '--encrypt-file', help='encrypt the input file', action='store_true')
    parser.add_argument('-df', '--decrypt-file', help='decrypt the input file', action='store_true')
    parser.add_argument('-o', '--output', help='output file', required=True)
    args = parser.parse_args()
    
    #get the password from the user
    if args.password is None:
        args.password = getpass.getpass()
        
    #encrypt or decrypt the input string or file
    if args.encrypt:
        if args.encrypt_file:
            result = encrypt_file(args.input, args.password, args.output_format, args.key_size)
        else:
            result = encrypt(args.input, args.password, args.input_format, args.output_format, args.key_size)
    elif args.decrypt:
        if args.decrypt_file:
            result = decrypt_file(args.input, args.password, args.input_format, args.key_size)
        else:
            result = decrypt(args.input, args.password, args.input_format, args.output_format, args.key_size)
    
    with open(args.output, 'wb') as f:
        f.write(result)

if __name__ == '__main__':
    main()
    


