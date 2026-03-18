import socket
import json
import sys
from datetime import datetime
from typing import Dict, Any


HOST = "0.0.0.0"
PORT = 16680


def log(level: str, msg: str) -> None:
    """Logging a stdout sin buffering para que fly logs los muestre en tiempo real."""
    print(f"[{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}] [{level}] {msg}", flush=True)


UNIT_MAP = {
    0x2B: 0.001,   # m³
    0x2C: 0.01,    # m³
    0x2D: 0.1,     # m³
    0x2E: 1.0,     # m³
    0x35: 0.0001,  # m³
}

# Tabla RSSI según la guía
RSSI_DBM_MAP = {
    0x00: -113, 0x01: -111, 0x02: -109, 0x03: -107,
    0x04: -105, 0x05: -103, 0x06: -101, 0x07: -99,
    0x08: -97,  0x09: -95,  0x0A: -93,  0x0B: -91,
    0x0C: -89,  0x0D: -87,  0x0E: -85,  0x0F: -83,
    0x10: -81,  0x11: -79,  0x12: -77,  0x13: -75,
    0x14: -73,  0x15: -71,  0x16: -69,  0x17: -67,
    0x18: -65,  0x19: -63,  0x1A: -61,  0x1B: -59,
    0x1C: -57,  0x1D: -55,  0x1E: -53,  0x1F: -51,
    0x63: None,  # Unknown
}


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bcd_bytes_to_digits(data: bytes) -> str:
    """
    Convierte bytes BCD a una cadena decimal.
    Ejemplo: b'\\x86\\x77\\x24' -> '867724'
    """
    digits = []
    for b in data:
        high = (b >> 4) & 0x0F
        low = b & 0x0F
        digits.append(str(high))
        digits.append(str(low))
    return "".join(digits)


def bcd_little_endian_to_digits(data: bytes) -> str:
    """
    BCD con lower byte priority.
    Se invierten los bytes y luego se leen como BCD.
    """
    return bcd_bytes_to_digits(data[::-1])


def little_endian_hex_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little", signed=False)


def checksum_mod256(data: bytes) -> int:
    return sum(data) % 256


def decode_alarm_bits_beco_family(st1: int, st2: int) -> Dict[str, bool]:
    """
    Mapeo ST1/ST2 según la sección:
    BECO X, BECO Y, B6 Lite VW y B9 VW.
    Si tu modelo es otro, esta parte hay que ajustarla.
    """
    return {
        "leakage_alarm": bool((st1 >> 2) & 1),
        "burst_alarm": bool((st1 >> 3) & 1),
        "tamper_alarm": bool((st1 >> 4) & 1),
        "freezing_alarm": bool((st1 >> 5) & 1),

        "low_battery_alarm": bool((st2 >> 0) & 1),
        "empty_pipe_alarm": bool((st2 >> 1) & 1),
        "reverse_flow_alarm": bool((st2 >> 2) & 1),
        "over_range_alarm": bool((st2 >> 3) & 1),
        "temperature_alarm": bool((st2 >> 4) & 1),
        "ee_error_alarm": bool((st2 >> 5) & 1),
    }


def parse_water_meter_payload(payload: bytes) -> Dict[str, Any]:
    """
    CMD 0x00 - Water meter payload
    ADDR 4
    Totalizer 4
    Uplink Interval 2
    Unit Indicator 1
    ST1 1
    ST2 1
    ICCID 10
    RSSI 1
    Total esperado: 24 bytes
    """
    if len(payload) != 24:
        raise ValueError(f"Payload water meter inválido. Esperado 24 bytes, recibido {len(payload)}")

    addr = payload[0:4]
    totalizer_raw = payload[4:8]
    interval_raw = payload[8:10]
    unit_raw = payload[10]
    st1 = payload[11]
    st2 = payload[12]
    iccid_raw = payload[13:23]
    rssi_raw = payload[23]

    meter_id = bcd_little_endian_to_digits(addr)
    totalizer_digits = bcd_little_endian_to_digits(totalizer_raw)
    interval_minutes = little_endian_hex_to_int(interval_raw)
    unit_factor = UNIT_MAP.get(unit_raw)
    iccid = bcd_bytes_to_digits(iccid_raw)
    rssi_dbm = RSSI_DBM_MAP.get(rssi_raw)

    totalizer_value = None
    if unit_factor is not None:
        try:
            totalizer_value = int(totalizer_digits) * unit_factor
        except ValueError:
            totalizer_value = None

    return {
        "meter_id": meter_id,
        "totalizer_digits": totalizer_digits,
        "totalizer_m3": totalizer_value,
        "uplink_interval_minutes": interval_minutes,
        "unit_indicator_hex": f"0x{unit_raw:02X}",
        "unit_factor_m3": unit_factor,
        "st1_hex": f"0x{st1:02X}",
        "st2_hex": f"0x{st2:02X}",
        "alarms": decode_alarm_bits_beco_family(st1, st2),
        "iccid": iccid,
        "rssi_hex": f"0x{rssi_raw:02X}",
        "rssi_dbm": rssi_dbm,
    }


def parse_bove_4g_frame(frame: bytes) -> Dict[str, Any]:
    """
    Estructura base water meter:
    Start Byte   1
    IMEI         7
    COMM         1
    ACK          1
    FCNT         1
    CMD          1
    Reserve      2
    Data Length  2   (little-endian)
    Payload      N
    Checksum     1
    End Byte     1
    """
    if len(frame) < 17:
        raise ValueError("Trama demasiado corta")

    if frame[0] != 0x88:
        raise ValueError(f"Start byte inválido: 0x{frame[0]:02X}")

    if frame[-1] != 0x22:
        raise ValueError(f"End byte inválido: 0x{frame[-1]:02X}")

    imei_raw = frame[1:8]
    comm = frame[8]
    ack = frame[9]
    fcnt = frame[10]
    cmd = frame[11]
    reserve = frame[12:14]
    data_length = little_endian_hex_to_int(frame[14:16])

    expected_total_len = 1 + 7 + 1 + 1 + 1 + 1 + 2 + 2 + data_length + 1 + 1
    if len(frame) != expected_total_len:
        raise ValueError(
            f"Longitud total inválida. Esperado {expected_total_len} bytes según Data Length={data_length}, "
            f"recibido {len(frame)}"
        )

    payload = frame[16:16 + data_length]
    received_checksum = frame[16 + data_length]
    calculated_checksum = checksum_mod256(frame[0:16 + data_length])

    imei_14 = bcd_bytes_to_digits(imei_raw)

    result = {
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "raw_hex": bytes_to_hex(frame),
        "start_byte_hex": f"0x{frame[0]:02X}",
        "imei_14": imei_14,
        "comm_hex": f"0x{comm:02X}",
        "is_4g": comm == 0x00,
        "ack_hex": f"0x{ack:02X}",
        "ack_enabled": ack == 0x00,
        "fcnt": fcnt,
        "cmd_hex": f"0x{cmd:02X}",
        "reserve_hex": bytes_to_hex(reserve),
        "data_length": data_length,
        "payload_hex": bytes_to_hex(payload),
        "checksum_received_hex": f"0x{received_checksum:02X}",
        "checksum_calculated_hex": f"0x{calculated_checksum:02X}",
        "checksum_ok": received_checksum == calculated_checksum,
        "end_byte_hex": f"0x{frame[-1]:02X}",
    }

    if cmd == 0x00:
        result["cmd_name"] = "MDU_WATER_METER_DATA"
        result["decoded_payload"] = parse_water_meter_payload(payload)
    elif cmd == 0x02:
        result["cmd_name"] = "VDU_VALVE_RESPONSE"
        result["decoded_payload"] = {
            "payload_note": "Respuesta a control de válvula. Este script base se enfoca en meter data."
        }
    else:
        result["cmd_name"] = "UNKNOWN"
        result["decoded_payload"] = {
            "payload_note": "CMD no implementado en este script."
        }

    return result


def build_ack_frame(imei_raw: bytes, fcnt: int, cmd: int) -> bytes:
    """
    Construye el frame ACK de respuesta al dispositivo.
    El servidor responde con:
      Start(0x88) + IMEI(7) + COMM(0x01 = server) + ACK(0x01 = ACK reply)
      + FCNT + CMD + Reserve(2) + DataLength(0x00,0x00) + Checksum + End(0x22)
    DataLength=0 → sin payload → frame de 17 bytes.
    """
    frame = bytearray()
    frame.append(0x88)           # Start byte
    frame.extend(imei_raw)       # IMEI 7 bytes
    frame.append(0x01)           # COMM: 0x01 = respuesta servidor
    frame.append(0x01)           # ACK: 0x01 = confirmación
    frame.append(fcnt)           # FCNT igual al recibido
    frame.append(cmd)            # CMD igual al recibido
    frame.extend([0x00, 0x00])   # Reserve
    frame.extend([0x00, 0x00])   # Data Length = 0
    checksum = checksum_mod256(bytes(frame))
    frame.append(checksum)
    frame.append(0x22)           # End byte
    return bytes(frame)


def run_udp_server(host: str = HOST, port: int = PORT) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    log("INFO", f"Servidor UDP escuchando en {host}:{port}")
    log("INFO", "Esperando paquetes de dispositivos 4G...")

    while True:
        data, addr = sock.recvfrom(4096)
        remote = f"{addr[0]}:{addr[1]}"
        log("INFO", f"Paquete recibido | from={remote} bytes={len(data)} hex={bytes_to_hex(data)}")

        try:
            decoded = parse_bove_4g_frame(data)
            log("OK", f"Trama decodificada | from={remote} imei={decoded.get('imei_14')} "
                      f"cmd={decoded.get('cmd_name')} checksum={'OK' if decoded.get('checksum_ok') else 'FAIL'}")

            # Loguear datos del medidor si es CMD 0x00
            dp = decoded.get("decoded_payload", {})
            if decoded.get("cmd_name") == "MDU_WATER_METER_DATA":
                log("DATA", f"meter_id={dp.get('meter_id')} "
                            f"totalizer_m3={dp.get('totalizer_m3')} "
                            f"interval_min={dp.get('uplink_interval_minutes')} "
                            f"rssi_dbm={dp.get('rssi_dbm')} "
                            f"iccid={dp.get('iccid')}")
                alarms = dp.get("alarms", {})
                active_alarms = [k for k, v in alarms.items() if v]
                if active_alarms:
                    log("ALARM", f"meter_id={dp.get('meter_id')} alarmas_activas={active_alarms}")

            # Imprimir JSON completo para trazabilidad total
            print(json.dumps(decoded, indent=2, ensure_ascii=False), flush=True)

            # Enviar ACK si el dispositivo lo solicita
            if decoded.get("ack_enabled"):
                imei_raw = data[1:8]
                fcnt = data[10]
                cmd = data[11]
                ack_frame = build_ack_frame(imei_raw, fcnt, cmd)
                sock.sendto(ack_frame, addr)
                log("ACK", f"ACK enviado a {remote} hex={bytes_to_hex(ack_frame)}")

        except Exception as e:
            log("ERROR", f"from={remote} error={e} hex={bytes_to_hex(data)}")


if __name__ == "__main__":
    run_udp_server()