text = input("input text :")
arti = '' 
i = len(text) - 1
while i >= 0:
    arti = arti + text[i]
    i = i - 1
print('Hasilnya : ', arti)