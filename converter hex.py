plaintext = input("Input plaintext : ") #normal ke hex

print(plaintext.encode('utf-8').hex())

hex = input("Input hex : ") #hex ke norma[]

print(bytes.fromhex(hex).decode('utf-8'))
