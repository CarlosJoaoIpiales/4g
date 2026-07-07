"""
Simulador de dispositivo BOVE 4G.
Construye un frame valido CMD 0x00 (Water Meter Data) y lo envia al servidor UDP.
Uso: python test_send_packet.py <IP_SERVIDOR> [PUERTO]
"""
import socket
import sys


def checksum_mod256(data: bytes) -> int:
    return sum(data) % 256


def build_test_frame() -> bytes:
    """
    Frame de prueba con datos simulados de medidor de agua.
    IMEI simulado:   86123456789012
    Meter ID:        12345678
    Totalizer:       00001234 (BCD little-endian) → 1234 * 0.001 = 1.234 m³
    Interval:        60 minutos
    Unit:            0x2B (×0.001 m³)
    ST1/ST2:         sin alarmas
    ICCID simulado:  89540000000000000000
    RSSI:            0x11 (-79 dBm)
    """
    frame = bytearray()

    # Start byte
    frame.append(0x88)

    # IMEI 7 bytes BCD: 86123456789012
    frame.extend(bytes([0x86, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12]))

    # COMM: 0x00 = 4G device
    frame.append(0x00)

    # ACK: 0x00 = solicita confirmacion
    frame.append(0x00)

    # FCNT: contador de frame
    frame.append(0x01)

    # CMD: 0x00 = Water Meter Data
    frame.append(0x00)

    # Reserve: 2 bytes
    frame.extend([0x00, 0x00])

    # Data Length: 24 bytes (little-endian)
    frame.extend([0x18, 0x00])

    # --- PAYLOAD 24 bytes ---

    # ADDR (Meter ID) 4 bytes BCD little-endian: 12345678
    frame.extend(bytes([0x78, 0x56, 0x34, 0x12]))

    # Totalizer 4 bytes BCD little-endian: 00001234
    frame.extend(bytes([0x34, 0x12, 0x00, 0x00]))

    # Uplink Interval 2 bytes little-endian: 60 minutos
    frame.extend([0x3C, 0x00])

    # Unit Indicator: 0x2B = ×0.001 m³
    frame.append(0x2B)

    # ST1: sin alarmas
    frame.append(0x00)

    # ST2: sin alarmas
    frame.append(0x00)

    # ICCID 10 bytes BCD: 89540000000000000000
    frame.extend(bytes([0x89, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    # RSSI: 0x11 = -79 dBm
    frame.append(0x11)

    # --- FIN PAYLOAD ---

    # Checksum
    checksum = checksum_mod256(bytes(frame))
    frame.append(checksum)

    # End byte
    frame.append(0x22)

    return bytes(frame)


def main():
    if len(sys.argv) < 2:
        print("Uso: python test_send_packet.py <IP_SERVIDOR> [PUERTO]")
        print("Ejemplo: python test_send_packet.py 137.184.157.170 16680")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 16680

    frame = build_test_frame()
    print(f"[INFO] Enviando paquete de prueba a {host}:{port}")
    print(f"[INFO] HEX: {frame.hex().upper()}")
    print(f"[INFO] Bytes: {len(frame)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(frame, (host, port))
    print("[OK]   Paquete enviado.")

    # Esperar ACK del servidor
    try:
        response, addr = sock.recvfrom(1024)
        print(f"[ACK]  Respuesta recibida desde {addr[0]}:{addr[1]}")
        print(f"[ACK]  HEX: {response.hex().upper()}")
    except socket.timeout:
        print("[WARN] No se recibio ACK en 5 segundos (puede ser normal si el servidor no envia respuesta aun)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
