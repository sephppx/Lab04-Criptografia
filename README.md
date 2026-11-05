# Laboratorio 04, Criptografía

## Descripción

Este laboratorio aborda dos escenarios relacionados con criptografía aplicada y análisis de tráfico de red.

En la primera actividad se implementa un servidor SSH dentro de un contenedor Docker, restringiendo explícitamente los algoritmos criptográficos utilizados durante la conexión. Posteriormente, se analiza el tráfico generado mediante Wireshark para determinar qué información puede ser observada por un tercero y qué contenido queda protegido mediante cifrado.

En la segunda actividad se analiza una captura de tráfico que contiene transacciones financieras protegidas mediante RSA-OAEP y AES-GCM. A partir de la captura se recupera un PIN cifrado mediante RSA, se deriva una clave AES-256 utilizando Scrypt y finalmente se descifran y verifican las transacciones.

## Estructura del proyecto

```text
LAB04/
├── Actividad1/
│   └── captura_ssh_lab04.pcapng
│
├── Actividad2/
│   ├── clave_privada.pem
│   ├── clave_publica.pem
│   ├── descifrar_transacciones.py
│   ├── transacciones_cifradas.pcap
│   └── transacciones_recuperadas.csv
│
├── Evidencias/
│   ├── 01_SSH_Configuracion_Efectiva.png
│   ├── 02_SSH_Conexion_Algoritmos.png
│   ├── 03_Wireshark_Client_Protocol.png
│   ├── 04_Wireshark_Server_Protocol.png
│   ├── 05_Wireshark_Algoritmos_SSH.png
│   ├── 06_Wireshark_Trafico_Cifrado.png
│   ├── 07_Wireshark_RSA_PIN.png
│   ├── 08_Wireshark_AESGCM.png
│   ├── 09_Python_Extraccion_RSA_PIN.png
│   ├── 10_Python_PIN_Recuperado.png
│   ├── 11_Python_Clave_AES.png
│   ├── 12_Python_Primera_Transaccion.png
│   └── 13_Python_Transacciones_Recuperadas.png
│
├── Informe/
│   └── LAB04_Criptografia.pdf
│
├── Dockerfile
├── sshd_config
└── README.md
```

## Actividad 1, servidor SSH

Se construyó un servidor SSH utilizando Docker sobre una imagen Ubuntu 24.04.

El servidor fue configurado para utilizar exclusivamente los siguientes algoritmos:

| Función | Algoritmo |
|---|---|
| Intercambio de claves | `curve25519-sha256` |
| Clave de host | `ssh-ed25519` |
| Cifrado | `aes256-ctr` |
| Integridad | `hmac-sha2-256` |

### Construcción de la imagen

Desde la carpeta principal del laboratorio:

```bash
docker build -t lab04-ssh .
```

### Ejecución del contenedor

```bash
docker run -d \
  --name lab04-ssh-server \
  -p 2222:22 \
  lab04-ssh
```

El puerto `22` del contenedor queda publicado en el puerto `2222` del equipo cliente.

### Verificación de la configuración

```bash
docker exec lab04-ssh-server sshd -T | \
grep -E '^(kexalgorithms|ciphers|macs|hostkeyalgorithms|hostkey) '
```

La configuración efectiva utilizada fue:

```text
ciphers aes256-ctr
macs hmac-sha2-256
kexalgorithms curve25519-sha256
hostkeyalgorithms ssh-ed25519
hostkey /etc/ssh/ssh_host_ed25519_key
```

### Conexión al servidor

```bash
ssh -p 2222 felipe@localhost
```

Para observar en detalle la negociación SSH:

```bash
ssh -vv -p 2222 felipe@localhost
```

Durante la conexión se verificó el uso de:

```text
curve25519-sha256
ssh-ed25519
aes256-ctr
hmac-sha2-256
```

### Análisis con Wireshark

La captura se realizó utilizando la interfaz de loopback y filtrando el tráfico mediante:

```text
tcp.port == 2222
```

El análisis permitió observar información que permanece visible para un tercero, entre ella:

- puertos, direcciones, tamaños y dirección de los paquetes;
- versiones del cliente y servidor OpenSSH;
- algoritmos anunciados durante la negociación SSH.

Después del intercambio de nuevas claves, Wireshark muestra el contenido de la sesión como tráfico cifrado, por lo que comandos, contraseñas y respuestas no aparecen directamente en texto legible.

La captura utilizada se encuentra en:

```text
Actividad1/captura_ssh_lab04.pcapng
```

## Actividad 2, recuperación de transacciones

La segunda actividad utiliza la captura:

```text
Actividad2/transacciones_cifradas.pcap
```

junto con las claves:

```text
Actividad2/clave_privada.pem
Actividad2/clave_publica.pem
```

El análisis permitió identificar:

```text
1 paquete RSA_PIN
40 paquetes AESGCM
```

### Dependencias de Python

El script utiliza principalmente:

```bash
pip3 install scapy cryptography
```

### Ejecución

Desde la carpeta principal del laboratorio:

```bash
python3 Actividad2/descifrar_transacciones.py
```

## Recuperación del PIN

El paquete `RSA_PIN` posee la siguiente estructura:

```text
RSA_PIN| + salt de 16 bytes + ciphertext RSA de 256 bytes
```

La salt recuperada fue:

```text
1a065da01a70284041b93dd58e988907
```

El ciphertext fue descifrado utilizando RSA-OAEP con SHA-256 y la clave privada proporcionada.

El PIN recuperado fue:

```text
4827
```

## Derivación de la clave AES

A partir del PIN y la salt se utilizó Scrypt con los parámetros:

```text
N = 16384
r = 8
p = 1
Longitud = 32 bytes
```

La clave AES-256 derivada fue:

```text
f64d739ad8bd559fcd4bde7b9aecb83ff28d200331da635d7409b7133b16eab7
```

## Descifrado mediante AES-GCM

Cada paquete `AESGCM` contiene:

```text
AESGCM| + nonce de 12 bytes + ciphertext + tag
```

El script extrae automáticamente estos campos y utiliza la clave AES-256 derivada para recuperar las transacciones.

AES-GCM permite además verificar la autenticidad de cada mensaje mediante su tag.

El resultado final fue:

```text
Paquetes AESGCM encontrados: 40
Transacciones recuperadas: 40
Transacciones verificadas correctamente: 40
```

La primera transacción recuperada fue:

```text
TRANSACCION COMPLETADA
ID=TRX-426477
DE=Diego Ramirez
A=Constanza Vidal
MONTO=763923
```

Las 40 transacciones recuperadas fueron exportadas automáticamente a:

```text
Actividad2/transacciones_recuperadas.csv
```

## Criptografía post-cuántica

Las claves RSA utilizadas en esta experiencia no pueden emplearse directamente para descifrar información protegida mediante un algoritmo post-cuántico diferente.

Los esquemas PQC utilizan mecanismos matemáticos y estructuras de claves propias. Por ejemplo, un mecanismo como ML-KEM requiere su propia pareja de claves y no es compatible con una clave privada RSA.

Por lo tanto, las claves RSA proporcionadas solamente permiten realizar operaciones compatibles con RSA y no pueden reutilizarse como claves de un esquema post-cuántico.

## Resultados principales

La experiencia permitió comprobar correctamente:

```text
Servidor SSH operativo mediante Docker
Configuración criptográfica SSH verificada
Conexión cliente-servidor establecida
Captura SSH analizada mediante Wireshark
PIN RSA recuperado: 4827
Clave AES-256 derivada mediante Scrypt
40 paquetes AES-GCM encontrados
40 transacciones recuperadas
40 transacciones autenticadas correctamente
```

## Informe

El informe final de la experiencia se encuentra en:

```text
Informe/LAB04_Criptografia.pdf
```

## Autor

**Felipe Nicolas Bustos López**  
Universidad Diego Portales  
Criptografía, Laboratorio 04