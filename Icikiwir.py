import sys
from time import sleep
import time

def print_lyrics():
    lines = [
        ("Beli ciki beli koyo", 0.1),
        ("Suki yo", 0.07),
        ("Ima anata ni omoi nosete", 0.1),
        ("Hora, sunao ni naru no watashi", 0.09 ),
        ("Kono saki motto soba ni ite mo ii ka na?", 0.1),
        ("Koi to koi ga kasanatte", 0.08),
        ("Suki yo", 0.07),
        ("Ima anata ni omoi todoke", 0.1),
        ("Nee, kizuitekuremasen ka?", 0.09),
        ("Doushiyou mo nai kurai", 0.1),
        ("Kokoro made suki ni natteiku", 0.05),

    ]

    delays = [0.5, 0.9, 0.8, 2.2, 1.8, 1.6, 0.8, 0.9, 1.2, 1.2, 10.3]

    for i, (line, char_delay) in enumerate(lines):
        for char in line:
            print(char, end='')
            sys.stdout.flush()
            sleep(char_delay)
        time.sleep(delays[i])
        print('')

print_lyrics()