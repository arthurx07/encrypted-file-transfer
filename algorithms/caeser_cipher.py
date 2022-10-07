#!/bin/env python

plaintext_sample = input('Introdueix el text a codificar: ')
# Nombre de posicions pel que se substitueix la lletra
shift_sample = 3

def caeser_encrypt(plaintext, shift):
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    modulo = len(characters)
    ciphertext = ''

    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            ciphertext+=characters[((characters.index(plaintext[i].upper())) + shift) % modulo]
        else:
            ciphertext += plaintext[i]

    return ciphertext

print(caeser_encrypt(plaintext_sample, shift_sample))
