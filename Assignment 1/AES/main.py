from aes import encrypt, decrypt, to_hex, to_word, cipher, key_expansion, decipher

if __name__ == '__main__':
    user_input = input('Type your message: ')
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    message = list(str.encode(user_input, 'utf-8'))

    encrypted_message = encrypt(message, key)
    print(f'Encrypted message: {to_hex(encrypted_message)}')
    decrypted_message = decrypt(encrypted_message, key)
    print(f'Decrypted message: {bytes(decrypted_message).decode("utf-8")}')
