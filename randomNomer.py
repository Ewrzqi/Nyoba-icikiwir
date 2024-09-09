import random

chance = random.random()
ind = ('+628')
nomor = random.randint(100000000, 999999999)
nomor2 = random.randint(1000000000, 9999999999)

if chance < 0.5:
    print(ind + str(nomor))
elif chance > 0.5:
    print(ind + str(nomor2))
    
