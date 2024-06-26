from PIL import Image

def encrypt_image(image_path, shift):
    # Open the image
    image = Image.open(image_path)

    # Get the pixel data
    pixels = list(image.getdata())

    # Encrypt the pixels
    encrypted_pixels = []
    for pixel in pixels:
        r, g, b = pixel
        encrypted_r = (r + shift) % 256
        encrypted_g = (g + shift) % 256
        encrypted_b = (b + shift) % 256
        encrypted_pixels.append((encrypted_r, encrypted_g, encrypted_b))

    # Create a new image with the encrypted pixels
    encrypted_image = Image.new(image.mode, image.size)
    encrypted_image.putdata(encrypted_pixels)

    # Save the encrypted image
    encrypted_image.save("encrypted_image.png")

def decrypt_image(image_path, shift):
    # Open the encrypted image
    encrypted_image = Image.open(image_path)

    # Get the encrypted pixel data
    encrypted_pixels = list(encrypted_image.getdata())

    # Decrypt the pixels
    decrypted_pixels = []
    for pixel in encrypted_pixels:
        r, g, b = pixel
        decrypted_r = (r - shift) % 256
        decrypted_g = (g - shift) % 256
        decrypted_b = (b - shift) % 256
        decrypted_pixels.append((decrypted_r, decrypted_g, decrypted_b))

    # Create a new image with the decrypted pixels
    decrypted_image = Image.new(encrypted_image.mode, encrypted_image.size)
    decrypted_image.putdata(decrypted_pixels)

    # Save the decrypted image
    decrypted_image.save("decrypted_image.png")

def main():
    print("Image Encryption/Decryption Program")
    print("-----------------------------------")

    while True:
        print("1. Encrypt Image")
        print("2. Decrypt Image")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            image_path = input("Enter the image path: ")
            shift = int(input("Enter the shift value: "))
            encrypt_image(image_path, shift)
            print("Image encrypted successfully!")

        elif choice == "2":
            image_path = input("Enter the encrypted image path: ")
            shift = int(input("Enter the shift value: "))
            decrypt_image(image_path, shift)
            print("Image decrypted successfully!")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
