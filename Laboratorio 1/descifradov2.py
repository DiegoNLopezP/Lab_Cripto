import sys
from scapy.all import *
from colorama import Fore, Style

# Función para calcular la puntuación de "naturalidad" de un texto en español
def calcular_puntuacion_espanol(texto):
    texto = texto.lower()
    puntuacion = 0
    for letra in texto:
        if letra in frecuencias_espanol:
            puntuacion += frecuencias_espanol[letra]
    return puntuacion

# Función para procesar paquetes ICMP
def procesar_paquete_icmp(pkt):
    global acumulado  # Declarar la variable acumulado como global
    if ICMP in pkt:
        # Obtener el campo de datos del paquete ICMP
        datos = pkt[ICMP].load

        # Verificar si hay suficientes bytes en los datos
        if len(datos) >= 9:
            # Obtener el noveno byte
            noveno_byte = datos[8:9].decode('latin-1')

            # Acumular el byte en una cadena completa
            acumulado += noveno_byte

# Nombre del archivo de captura de Wireshark desde la línea de comandos
archivo_captura = sys.argv[1]

# Leer la captura de Wireshark
paquetes = rdpcap(archivo_captura)

# Inicializar una cadena acumulativa
acumulado = ""

# Frecuencias de letras en español
frecuencias_espanol = {
    'a': 0.1172, 'b': 0.0220, 'c': 0.0402, 'd': 0.0501, 'e': 0.1218, 'f': 0.0069, 'g': 0.0170,
    'h': 0.0070, 'i': 0.0625, 'j': 0.0044, 'k': 0.0002, 'l': 0.0497, 'm': 0.0315, 'n': 0.0671,
    'o': 0.0868, 'p': 0.0251, 'q': 0.0088, 'r': 0.0687, 's': 0.0798, 't': 0.0463, 'u': 0.0393,
    'v': 0.0090, 'w': 0.0001, 'x': 0.0022, 'y': 0.0090, 'z': 0.0052,
}

# Variables para rastrear la combinación más probable de texto natural en español
mejor_corrimiento = 0
mejor_resultado = ""
max_puntuacion = 0

# Procesar cada paquete ICMP y concatenar los novenos bytes en ASCII
for pkt in paquetes:
    procesar_paquete_icmp(pkt)

# Aplicar cifrado César inverso a la cadena completa con todos los corrimientos
for desplazamiento in range(26):
    resultado_cesar = ""
    for caracter in acumulado:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter_cesar = chr(((ord(caracter) - ord('A' if mayuscula else 'a') - desplazamiento) % 26) + ord('A' if mayuscula else 'a'))
            resultado_cesar += caracter_cesar
        else:
            resultado_cesar += caracter

    # Calcular la puntuación de "naturalidad" en español
    puntuacion_espanol = calcular_puntuacion_espanol(resultado_cesar)

    # Encontrar la combinación más probable en español
    if puntuacion_espanol > max_puntuacion:
        mejor_corrimiento = desplazamiento
        mejor_resultado = resultado_cesar
        max_puntuacion = puntuacion_espanol

# Calcular el ancho máximo del número de corrimiento
ancho_corrimiento = len(str(25))

# Encontrar la longitud máxima de línea para mantener los espacios alineados
longitud_maxima_linea = max(len(numero_corrimiento) for numero_corrimiento in [str(desplazamiento).rjust(ancho_corrimiento) for desplazamiento in range(26)])

# Imprimir solo el número de corrimiento y el texto cifrado, destacando la combinación más probable en español en verde
for desplazamiento in range(26):
    resultado_cesar = ""
    for caracter in acumulado:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter_cesar = chr(((ord(caracter) - ord('A' if mayuscula else 'a') - desplazamiento) % 26) + ord('A' if mayuscula else 'a'))
            resultado_cesar += caracter_cesar
        else:
            resultado_cesar += caracter

    numero_corrimiento = str(desplazamiento).rjust(ancho_corrimiento)
    espacio_extra = longitud_maxima_linea - len(numero_corrimiento)
    espacio = " " * espacio_extra
    if desplazamiento == mejor_corrimiento:
        print(Fore.GREEN + f"{numero_corrimiento} {espacio}{resultado_cesar}" + Style.RESET_ALL)
    else:
        print(f"{numero_corrimiento} {espacio}{resultado_cesar}")

