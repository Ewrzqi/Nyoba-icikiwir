rotate13 = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234')

def rot13(txt):
    return txt.translate(rotate13)
txt = input("Input plaintext : ")

print("Hasil encrypt : " + rot13(txt))
encrypt = rot13(txt)
print("Hasil decrypt : " + rot13(encrypt))
