from pathlib import Path

import csv

from scapy.all import rdpcap, TCP, Raw

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = Path(__file__).resolve().parent

PCAP_FILE = BASE_DIR / "transacciones_cifradas.pcap"
PRIVATE_KEY_FILE = BASE_DIR / "clave_privada.pem"


def main():
    paquetes = rdpcap(str(PCAP_FILE))

    print(f"Paquetes totales en la captura: {len(paquetes)}")

    rsa_payload = None
    paquetes_aes = []

    for paquete in paquetes:
        if TCP in paquete and Raw in paquete:
            payload = bytes(paquete[Raw].load)

            if payload.startswith(b"RSA_PIN|"):
                rsa_payload = payload

            elif payload.startswith(b"AESGCM|"):
                paquetes_aes.append(payload)

    if rsa_payload is None:
        raise ValueError("No se encontró el paquete RSA_PIN.")

    print("Paquetes RSA_PIN encontrados: 1")
    print(f"Paquetes AESGCM encontrados: {len(paquetes_aes)}")
    print(f"Longitud payload RSA_PIN: {len(rsa_payload)} bytes")

    etiqueta = rsa_payload[:8]
    salt = rsa_payload[8:24]
    pin_cifrado = rsa_payload[24:]

    print()
    print("=== RSA_PIN ===")
    print(f"Etiqueta: {etiqueta.decode()}")
    print(f"Salt: {salt.hex()}")
    print(f"Longitud salt: {len(salt)} bytes")
    print(f"Longitud PIN cifrado: {len(pin_cifrado)} bytes")

    # ------------------------------------------------------
    # Cargar clave privada RSA
    # ------------------------------------------------------

    with open(PRIVATE_KEY_FILE, "rb") as archivo:
        clave_privada = serialization.load_pem_private_key(
            archivo.read(),
            password=None
        )

    print()
    print("=== DESCIFRADO RSA ===")
    print(f"Tamaño clave RSA: {clave_privada.key_size} bits")

    pin_bytes = clave_privada.decrypt(
        pin_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    pin = pin_bytes.decode("utf-8")

    print("Algoritmo: RSA-OAEP con SHA-256")
    print(f"PIN recuperado: {pin}")
    print(f"Longitud PIN: {len(pin)} dígitos")

    # ------------------------------------------------------
    # Derivar clave AES-256 mediante Scrypt
    # ------------------------------------------------------

    print()
    print("=== DERIVACIÓN DE CLAVE AES ===")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    clave_aes = kdf.derive(pin_bytes)

    print("Algoritmo: Scrypt")
    print(f"N: {2**14}")
    print("r: 8")
    print("p: 1")
    print(f"Salt: {salt.hex()}")
    print(f"Longitud clave AES: {len(clave_aes)} bytes")
    print(f"Clave AES-256: {clave_aes.hex()}")

    # ------------------------------------------------------
    # Descifrar todas las transacciones AES-GCM
    # ------------------------------------------------------

    print()
    print("=== TRANSACCIONES AES-GCM ===")

    aesgcm = AESGCM(clave_aes)

    transacciones_recuperadas = []

    for numero, payload_aes in enumerate(paquetes_aes, start=1):

        etiqueta_aes = payload_aes[:7]
        nonce = payload_aes[7:19]
        ciphertext_y_tag = payload_aes[19:]

        if etiqueta_aes != b"AESGCM|":
            print(f"[{numero}] Paquete ignorado: etiqueta no válida")
            continue

        try:
            mensaje_descifrado = aesgcm.decrypt(
                nonce,
                ciphertext_y_tag,
                None
            )

            mensaje = mensaje_descifrado.decode("utf-8")

            partes = mensaje.split("|")

            estado = partes[0]

            datos = {}

            for parte in partes[1:]:
                if "=" in parte:
                    clave, valor = parte.split("=", 1)
                    datos[clave] = valor

            transaccion = {
                "estado": estado,
                "id": datos.get("ID", ""),
                "de": datos.get("DE", ""),
                "a": datos.get("A", ""),
                "monto": datos.get("MONTO", "")
            }

            transacciones_recuperadas.append(transaccion)

            print()
            print(f"[{numero:02d}] {estado}")
            print(f"     ID:    {transaccion['id']}")
            print(f"     DE:    {transaccion['de']}")
            print(f"     A:     {transaccion['a']}")
            print(f"     MONTO: {transaccion['monto']}")
            print("     AES-GCM: AUTENTICIDAD VERIFICADA")

        except Exception as error:
            print()
            print(f"[{numero:02d}] ERROR AL DESCIFRAR")
            print(f"     {error}")

    print()
    print("========================================")
    print("RESUMEN")
    print("========================================")
    print(f"Paquetes AESGCM encontrados: {len(paquetes_aes)}")
    print(
        f"Transacciones recuperadas: "
        f"{len(transacciones_recuperadas)}"
    )
    print(
        f"Transacciones verificadas correctamente: "
        f"{len(transacciones_recuperadas)}"
    )

    # ------------------------------------------------------
    # Guardar resultados en CSV
    # ------------------------------------------------------

    archivo_salida = BASE_DIR / "transacciones_recuperadas.csv"

    with open(
        archivo_salida,
        "w",
        newline="",
        encoding="utf-8"
    ) as archivo_csv:

        campos = [
            "ID",
            "REMITENTE",
            "DESTINATARIO",
            "MONTO",
            "ESTADO"
        ]

        writer = csv.DictWriter(
            archivo_csv,
            fieldnames=campos
        )

        writer.writeheader()

        for transaccion in transacciones_recuperadas:
            writer.writerow({
                "ID": transaccion["id"],
                "REMITENTE": transaccion["de"],
                "DESTINATARIO": transaccion["a"],
                "MONTO": transaccion["monto"],
                "ESTADO": transaccion["estado"]
            })

    print()
    print(
        f"Resultados guardados en: "
        f"{archivo_salida.name}"
    )

if __name__ == "__main__":
    main()