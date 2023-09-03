import sys

def cifrado_cesar(texto, corrimiento):
    resultado = []
    for char in texto:
        if char.isalpha():
            if char.islower():
                nuevo_char = chr(((ord(char) - ord('a') + corrimiento) % 26) + ord('a'))
            else:
                nuevo_char = chr(((ord(char) - ord('A') + corrimiento) % 26) + ord('A'))
            resultado.append(nuevo_char)
        else:
            resultado.append(char)
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Uso: python cifrado_cesar.py <texto> <corrimiento>")
    
    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])
    texto_cifrado = cifrado_cesar(texto, corrimiento)
    
    sys.stdout.write(texto_cifrado)

