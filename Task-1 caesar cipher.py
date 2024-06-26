#Caesar Cipher Encryptor/Decryptor#
def caesar_cipher(text, shift, mode):
    result = ''
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
        elif char.isdigit():
            shifted_char = str((int(char) + shift) % 10)
        else:
            shifted_char = char
        result += shifted_char
    return result
def main():
    message = input("Enter the message: ")
    shift =int(input("Enter the shift value: "))
    mode = input("Do you want to E for Encrypt or D for Decrypt? ")
    if mode.upper() == 'E':
        encrypted_message = caesar_cipher(message, shift, mode)
        print(f"Encrypted message: {encrypted_message}")
    elif mode.upper() == 'D':
        decrypted_message = caesar_cipher(message, -shift, mode)
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Invalid mode. Please enter 'E' for encryption or 'D' for decryption.")
if __name__ == "__main__":
    main()
