import PySimpleGUI as sg
import base64
from string import ascii_uppercase, ascii_lowercase

# Fungsi encoding untuk Base64
def base64_encode(plain):
    encoded = base64.b64encode(plain.encode('utf-8'))
    return encoded.decode('utf-8')

# Fungsi encoding untuk Vigenere
def vigenere_encode(plaintext, keyword):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encoded = ""
    keyword_repeated = ""
    keyword_index = 0

    for char in plaintext:
        if char.upper() in alphabet:
            keyword_repeated += keyword[keyword_index % len(keyword)].upper()
            keyword_index += 1
        else:
            keyword_repeated += char

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.upper() in alphabet:
            shift = alphabet.index(keyword_repeated[i].upper())
            if char.isupper():
                encoded += alphabet[(alphabet.index(char) + shift) % len(alphabet)]
            else:
                encoded += alphabet[(alphabet.index(char.upper()) + shift) % len(alphabet)].lower()
        else:
            encoded += char

    return encoded

# Fungsi encoding untuk Caesar
def caesar_encode(plain, key):
    output_text = ""
    for char in plain:
        if char.isupper():
            output_text += chr((ord(char) + key - 65) % 26 + 65)      
        elif char.islower():
            output_text += chr((ord(char) + key - 97) % 26 + 97)
        elif char.isnumeric():
            output_text += chr((ord(char) + key - 48) % 10 + 48)
        else:
            output_text += char  
    return output_text

# Fungsi encoding untuk ROT13
def rot13_encode(plain):
    rotate13 = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234'
    )
    return plain.translate(rotate13)

# Fungsi encoding untuk Reverse
def reverse_encode(plain):
    return plain[::-1]

# Fungsi encoding untuk Atbash
def atbash_encode(plain):
    enc = ""
    for char in plain:
        if char in ascii_uppercase:
            enc += ascii_uppercase[-(ascii_uppercase.index(char) + 1)]
        elif char in ascii_lowercase:
            enc += ascii_lowercase[-(ascii_lowercase.index(char) + 1)]
        else:
            enc += char
    return enc

# Fungsi encoding untuk Morse
def morse_encode(plain):
    morse_code_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 
        'Z': '--..', '0': '-----', '1': '.----', '2': '..---', 
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', 
        '7': '--...', '8': '---..', '9': '----.', ' ': '/'
    }
    return ' '.join(morse_code_dict.get(char.upper(), '') for char in plain)

# Fungsi encoding untuk XOR
def xor_encode(plain, key):
    encoded = ''.join(chr(ord(c) ^ key) for c in plain)
    return encoded

# Fungsi encoding untuk Binary
def binary_encode(plain):
    return ' '.join(format(ord(char), '08b') for char in plain)

# Fungsi encoding untuk Hexadecimal
def hex_encode(plain):
    return ' '.join(format(ord(char), 'x') for char in plain)

# Fungsi encoding untuk Oktal
def octal_encode(plain):
    return ' '.join(format(ord(char), 'o') for char in plain)

# Fungsi encoding untuk Desimal
def decimal_encode(plain):
    return ' '.join(str(ord(char)) for char in plain)

# Deklarasi fungsi decode
def base64_decode(cipher):
    try:
        decoded = base64.b64decode(cipher)
        return decoded.decode('utf-8')
    except Exception as e:
        return f"Invalid Base64 input: {e}"

def vigenere_decode(ciphertext, keyword):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    decoded = ""
    keyword_repeated = ""
    keyword_index = 0

    for char in ciphertext:
        if char.upper() in alphabet:
            keyword_repeated += keyword[keyword_index % len(keyword)].upper()
            keyword_index += 1
        else:
            keyword_repeated += char

    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.upper() in alphabet:
            shift = alphabet.index(keyword_repeated[i].upper())
            if char.isupper():
                decoded += alphabet[(alphabet.index(char) - shift) % len(alphabet)]
            else:
                decoded += alphabet[(alphabet.index(char.upper()) - shift) % len(alphabet)].lower()
        else:
            decoded += char

    return decoded

def vigenere_bruteforce(ciphertext):
    possible_keywords = ["KEY1", "KEY2", "KEY3"]  
    results = []

    for keyword in possible_keywords:
        decoded = vigenere_decode(ciphertext, keyword)
        results.append(f"Keyword {keyword}: {decoded}")
    return results

def caesar_decode(cipher, key):
    output_text = ""
    for i in range(len(cipher)):
        char = cipher[i]
        if char.isupper():
            output_text += chr((ord(char) - key - 65) % 26 + 65)      
        elif char.isnumeric():
            output_text += chr((ord(char) - key - 48) % 10 + 48)
        elif char.islower():
            output_text += chr((ord(char) - key - 97) % 26 + 97)
        else:
            output_text += char  
    return output_text

def caesar_bruteforce(cipher):
    results = []
    for key in range(1, 26):  
        decoded = caesar_decode(cipher, key)
        results.append(f"Key {key}: {decoded}")
    return results

def rot13_decode(cipher):
    rotate13 = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234'
    )
    return cipher.translate(rotate13)

def bruteforce_rot(txt):
    results = []
    for key in range(1, 26):
        rotate = str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            ''.join(chr((ord(char) - key - 65) % 26 + 65) if char.isupper() else
                    chr((ord(char) - key - 97) % 26 + 97) if char.islower() else
                    chr((ord(char) - key - 48) % 10 + 48) if char.isnumeric() else char
                    for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
        )
        results.append(f"Key {key}: {txt.translate(rotate)}")
    return results

def reverse_decode(cipher):
    return cipher[::-1]

def atbash_decode(enc):
    dec = ""
    for char in enc:
        if char in ascii_uppercase:
            dec += ascii_uppercase[-(ascii_uppercase.index(char) + 1)]
        elif char in ascii_lowercase:
            dec += ascii_lowercase[-(ascii_lowercase.index(char) + 1)]
        else:
            dec += char
    return dec

def whitespace_decode(cipher):
    firstType = ' '
    secondType = ' '
    binaryString = ''

    for char in cipher: 
        if char == firstType: 
            binaryString += '0'
        else:
            binaryString += '1'

    def binary_to_text(binary_string):
        n = 8
        chunks = [binary_string[i:i+n] for i in range(0, len(binary_string), n)]

        plaintext = ''
        for chunk in chunks:
            if len(chunk) == 8:
                decimal_value = int(chunk, 2)
                plaintext += chr(decimal_value)
        return plaintext

    return binary_to_text(binaryString)

# Fungsi decoding untuk Binary
def binary_decode(cipher_text):
    ascii_values = cipher_text.split()
    return ''.join(chr(int(b, 2)) for b in ascii_values)

# Fungsi decoding untuk Hexadecimal
def hex_decode(cipher_text):
    ascii_values = cipher_text.split()
    return ''.join(chr(int(h, 16)) for h in ascii_values)

# Fungsi decoding untuk Oktal
def octal_decode(cipher_text):
    ascii_values = cipher_text.split()
    return ''.join(chr(int(o, 8)) for o in ascii_values)

# Fungsi decoding untuk Desimal
def decimal_decode(cipher_text):
    ascii_values = cipher_text.split()
    return ''.join(chr(int(d, 10)) for d in ascii_values)

def morse_decode(morse_input):
    morse_code_dict = {
        '.-': 'A', '-...': 'B', '-..': 'D', '-..-': 'X',
        '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1',
        '..---': '2', '...--': '3', '....-': '4', '.....': '5',
        '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '/': ' '
    }
    morse_words = morse_input.split(' / ')
    decoded_message = []

    for word in morse_words:
        morse_chars = word.split(' ')
        decoded_word = ''.join(morse_code_dict.get(char, '') for char in morse_chars)
        decoded_message.append(decoded_word)

    return ' '.join(decoded_message)

def xor_decode(cipher, key):
    decoded = ''.join(chr(ord(c) ^ key) for c in cipher)
    return decoded

def xor_bruteforce(cipher):
    results = []
    for key in range(1, 26):  
        decoded = xor_decode(cipher, key)
        results.append(f"Key {key}: {decoded}")
    return results


# GUI
layout = [
    [sg.Text('Pilih Encode/Decoder:'), sg.Combo(['Base64', 'Vigenere', 'Caesar', 'ROT13', 'Reverse', 'Atbash', 'Morse', 'XOR', 'Binary', 'Hex', 'Octal', 'Decimal'], key='text')],
    [sg.Text('Masukkan Cipher Text:'), sg.InputText(key='-CIPHER-')],
    [sg.Text('Masukkan Key ( Caesar/Vigenere/XOR ):'), sg.InputText(key='-KEY-')],
    [sg.Checkbox('Brute Force ( Caesar/Vigenere/ROT13 )', key='-BRUTE-')],
    [sg.Button('Decode', size=(6, 2), button_color=('white', 'blue'), border_width=5), sg.Button('Encode',   size=(6, 2), button_color=('white', 'green'), border_width=5), sg.Button(image_filename='F:/Coba/uski/clear3.png', size=(1, 1), pad=(0, 0), button_color='grey', border_width=5, key='Clear'), sg.Button('Exit', size=(6, 2), button_color=('white', 'red'), border_width=5)],
    [sg.Output(size=(100, 20), key='-OUTPUT-')]
]

window = sg.Window('Suki Decoder', layout)

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == 'Exit':
        break
    
    cipher_text = values['-CIPHER-']
    key = values['-KEY-']
    method = values['text']
    brute_force = values['-BRUTE-']

    if event == 'Encode':
        if brute_force:
            sg.popup('Brute force tidak didukung untuk metode ini. Silakan matikan bruteforce!')
            continue
        elif method == 'Base64':
            print("Hasil enkripsi:", base64_encode(cipher_text))
        elif method == 'Vigenere' and key:
            print("Hasil enkripsi:", vigenere_encode(cipher_text, key))
        elif method == 'Caesar' and key.isdigit():
            print("Hasil enkripsi:", caesar_encode(cipher_text, int(key)))
        elif method == 'ROT13':
            print("Hasil enkripsi:", rot13_encode(cipher_text))
        elif method == 'Reverse':
            print("Hasil enkripsi:", reverse_encode(cipher_text))
        elif method == 'Atbash':
            print("Hasil enkripsi:", atbash_encode(cipher_text))
        elif method == 'Morse':
            print("Hasil enkripsi:", morse_encode(cipher_text))
        elif method == 'XOR' and key.isdigit():
            print("Hasil enkripsi:", xor_encode(cipher_text, int(key)))
        elif  method == 'Binary':
            print("Hasil enkripsi:", binary_encode(cipher_text))
        elif method ==  'Hex':
            print("Hasil enkripsi:", hex_encode(cipher_text))
        elif method  == 'Octal':
            print("Hasil enkripsi:", octal_encode(cipher_text))
        elif method ==  'Decimal':
            print("Hasil enkripsi:", decimal_encode(cipher_text))
        else:
            print("Metode atau kunci tidak valid.")
    
    elif event == 'Decode':
        if  brute_force:             
            if method not in ['Vigenere', 'Caesar', 'ROT13', 'XOR']:  # Cek jika metode tidak mendukung brute force
                sg.popup('Brute force tidak didukung untuk metode ini. Silakan matikan bruteforce!')
                continue  # Kembali ke awal loop untuk tidak melanjutkan proses decoding

        elif method == 'Base64':
            print("Hasil decoding:", base64_decode(cipher_text))
        elif method == 'Vigenere':
            if brute_force:
                results = vigenere_bruteforce(cipher_text)
                for result in results:
                    print(result)
            elif key:
                print("hasil dekripsi:", vigenere_decode(cipher_text, key))
            else:
                print("jangan lupa masukkan keynya.")
        elif method == 'Caesar':
            if brute_force:
                results = caesar_bruteforce(cipher_text)
                for result in results:
                    print(result)
            elif key.isdigit():
                print("hasil dekripsi:", caesar_decode(cipher_text, int(key)))
            else:
                print("key untuk caesar harus dalam bentuk angka.")
        elif method == 'ROT13':
            if brute_force:
                results = bruteforce_rot(cipher_text)
                for result in results:
                    print(result)
        elif method == 'Reverse':  
            print("Hasil decoding:", reverse_decode(cipher_text))
        elif method == 'Atbash':
            print("Hasil decoding:", atbash_decode(cipher_text))
        elif method == 'Morse':
            print("Hasil decoding:", morse_decode(cipher_text))
        elif method == 'XOR' and key.isdigit():
            if brute_force:
                results = xor_bruteforce(cipher_text)
                for result in results:
                    print(result)
            elif key.isdigit():
                print("hasil dekripsi:", xor_decode(cipher_text, int(key)))
            else:
                print("key untuk XOR harus dalam bentuk angka.")
        elif  method == 'Binary':
            print("Hasil dekripsi:", binary_decode(cipher_text))
        elif  method == 'Octal':
            print("Hasil dekripsi:", octal_decode(cipher_text))
        elif method  == 'Decimal':
            print("Hasil dekripsi:", decimal_decode(cipher_text))
        elif method  == 'Hex':
            print ("Hasil dekripsi:", hex_decode(cipher_text))
        else:
            print("Metode atau kunci tidak valid.")
    elif event == 'Clear':
        window['-OUTPUT-'].update('')
        window['-KEY-'].update('')   
        window['-CIPHER-'].update('')   
window.close()
