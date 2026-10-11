#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESP32 TLV Extcap for Wireshark

- Đọc dữ liệu từ serial (USB CDC / UART) với format:
    SYNC(0xAA55) + TOTAL_LEN(2B, BE) + VER(1B) + TLVs...

  IMPORTANT: TOTAL_LEN is the *full frame length* as sent by the ESP32 firmware
  (includes SYNC + TOTAL_LEN + VER + all TLVs).

- TLVs:
    0x01: TIMESTAMP (8 bytes, uint64, microseconds since boot, BE)
    0x02: DIRECTION (1 byte, 0=RX, 1=TX)
    0x03: SEQ (4 bytes, uint32, BE)
    0x10: PACKET_DATA (N bytes, raw Ethernet frame)
    0x11: CRC32 (4 bytes, uint32, BE) - must be the last TLV

  CRC32 is computed over bytes from VER (frame[4]) up to (but excluding) the CRC32 TLV.

- Ghi ra FIFO cho Wireshark theo format PCAP (DLT_EN10MB).
"""

import errno
import os
import signal
import struct
import sys
import time
import zlib

try:
    import serial  # pyserial
except ImportError:
    serial = None

MAX_TOTAL_LEN = 65535  # Bảo vệ khi dữ liệu bị lỗi

EXTCAP_INTERFACE_NAME = "esp32-tlv"
EXTCAP_INTERFACE_DISPLAY = "ESP32 TLV Sniffer"
EXTCAP_VERSION = "1.1.0"

STATS_ENABLED = os.getenv("ESP32_TLV_STATS", "0") not in ("0", "", "false", "False")

# ==========================
# Stop handling (Wireshark stop capture / Ctrl+C)
# ==========================

_STOP_REQUESTED = False


def _request_stop(signum=None, frame=None):
    # Keep handler minimal/safe
    global _STOP_REQUESTED
    _STOP_REQUESTED = True


def _install_signal_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _request_stop)
            except Exception:
                # Not all signals are supported in all environments
                pass


def _fifo_consumer_alive(fifo) -> bool:
    """Best-effort check whether Wireshark is still connected to the named pipe.

    On Windows, Wireshark may stop capture while no packets are flowing. In that case
    this extcap process won't attempt any writes, so it would never see BrokenPipe and
    would keep the COM port open. To avoid this, periodically probe the pipe using
    FlushFileBuffers() (no data written).
    """
    if fifo is None:
        return False

    if os.name != "nt":
        # On POSIX, Wireshark usually terminates the extcap process; keep behavior.
        return True

    try:
        import ctypes
        import msvcrt

        kernel32 = ctypes.windll.kernel32
        handle = msvcrt.get_osfhandle(fifo.fileno())

        ok = kernel32.FlushFileBuffers(ctypes.c_void_p(handle))
        if ok:
            return True

        err = kernel32.GetLastError()
        # ERROR_BROKEN_PIPE=109, ERROR_NO_DATA=232, ERROR_PIPE_NOT_CONNECTED=233, ERROR_INVALID_HANDLE=6
        if err in (109, 232, 233, 6):
            return False

        # Unknown error: don't force-stop (avoid false positives)
        return True
    except Exception:
        # If probing fails, keep running (fall back to BrokenPipe-on-write)
        return True


# ==========================
# Helper: in ra theo format extcap
# ==========================

def print_interfaces():
    """
    --extcap-interfaces
    """
    sys.stdout.write(f"extcap {{version={EXTCAP_VERSION}}}\n")
    sys.stdout.write(
        f"interface {{value={EXTCAP_INTERFACE_NAME}}}"
        f"{{display={EXTCAP_INTERFACE_DISPLAY}}}\n"
    )


def print_dlts():
    """
    --extcap-dlts
    """
    # DLT=1 => EN10MB (Ethernet)
    sys.stdout.write("dlt {number=1}{name=EN10MB}{display=Ethernet}\n")


def print_config():
    """
    --extcap-config
    Khai báo các options cho Wireshark GUI (chọn serial + baud)
    """
    # arg cho serial device
    sys.stdout.write(
        "arg {number=0}{call=--serial}{display=Serial port}"
        "{type=string}{tooltip=Serial device (e.g. COM3 or /dev/ttyACM0)}"
        "{required=true}\n"
    )

    # arg cho baud rate
    sys.stdout.write(
        "arg {number=1}{call=--baud}{display=Baud rate}"
        "{type=integer}{range=9600,921600}{default=115200}"
        "{tooltip=Serial baud rate}{required=true}\n"
    )


# ==========================
# Helper: PCAP writer
# ==========================

def write_pcap_global_header(fifo):
    """
    Ghi PCAP global header vào FIFO.
    DLT_EN10MB = 1
    """
    magic_number = 0xA1B2C3D4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # DLT_EN10MB

    header = struct.pack(
        "<IHHIIII",
        magic_number,
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        network
    )
    fifo.write(header)
    fifo.flush()


def write_pcap_packet(fifo, ts_us, packet_bytes):
    """
    Ghi 1 packet record vào PCAP.

    ts_us: timestamp microseconds (uint64)
    packet_bytes: raw Ethernet frame
    """
    if packet_bytes is None:
        return

    ts_sec = ts_us // 1_000_000
    ts_usec = ts_us % 1_000_000

    incl_len = len(packet_bytes)
    orig_len = len(packet_bytes)

    # Packet header
    pkt_hdr = struct.pack(
        "<IIII",
        int(ts_sec),
        int(ts_usec),
        incl_len,
        orig_len
    )

    fifo.write(pkt_hdr)
    fifo.write(packet_bytes)
    fifo.flush()


# ==========================
# Helper: TLV parser
# ==========================

SYNC_BYTES = b"\xAA\x55"

TLV_TYPE_TIMESTAMP = 0x01
TLV_TYPE_DIRECTION = 0x02
TLV_TYPE_SEQ = 0x03
TLV_TYPE_PACKET_DATA = 0x10
TLV_TYPE_CRC32 = 0x11


def parse_tlv_frame_and_validate(frame: bytes):
    """Parse one TLV frame and validate CRC32.

    Returns:
        (ok, ts_us, direction, seq, packet_bytes)
    """
    if len(frame) < 5:
        return (False, None, None, None, None)

    # frame[0:2] = SYNC, frame[2:4] = TOTAL_LEN (already validated externally)
    ver = frame[4]
    if ver != 0x01:
        return (False, None, None, None, None)

    payload = frame[5:]
    offset = 0

    ts_us = None
    direction = 0
    seq = None
    packet_data = None
    crc_value = None

    # Track CRC TLV (absolute offset in frame)
    crc_tlv_start = None

    while offset + 3 <= len(payload):
        t = payload[offset]
        l = (payload[offset + 1] << 8) | payload[offset + 2]
        tlv_start_in_payload = offset
        offset += 3

        if offset + l > len(payload):
            return (False, None, None, None, None)

        v = payload[offset:offset + l]
        offset += l

        if t == TLV_TYPE_TIMESTAMP and l == 8:
            ts_us = int.from_bytes(v, "big", signed=False)
        elif t == TLV_TYPE_DIRECTION and l >= 1:
            direction = v[0]
        elif t == TLV_TYPE_SEQ and l == 4:
            seq = int.from_bytes(v, "big", signed=False)
        elif t == TLV_TYPE_PACKET_DATA and l > 0:
            packet_data = bytes(v)
        elif t == TLV_TYPE_CRC32 and l == 4:
            # CRC32 TLV must be the last TLV
            if offset != len(payload):
                return (False, None, None, None, None)
            crc_value = int.from_bytes(v, "big", signed=False)
            crc_tlv_start = 5 + tlv_start_in_payload  # absolute offset in frame
        else:
            pass

    if crc_value is None or crc_tlv_start is None:
        return (False, None, None, None, None)

    # CRC region: from VER (frame[4]) up to (excluding) CRC32 TLV start
    computed_crc = zlib.crc32(frame[4:crc_tlv_start]) & 0xFFFFFFFF
    if computed_crc != crc_value:
        return (False, None, None, None, None)

    return (True, ts_us, direction, seq, packet_data)


def read_frames_from_serial(ser, fifo):
    buf = bytearray()

    ok_frames = 0
    bad_len = 0
    crc_or_parse_fail = 0
    seq_gap_events = 0
    seq_missing = 0
    last_seq = None
    last_stat_ts = time.time()

    while True:
        if _STOP_REQUESTED:
            break

        try:
            chunk = ser.read(1024)
            if not chunk:
                # timeout -> thử lại
                if os.name == "nt" and not _fifo_consumer_alive(fifo):
                    return
                if STATS_ENABLED and (time.time() - last_stat_ts) >= 5:
                    sys.stderr.write(
                        f"[STATS] ok={ok_frames} bad_len={bad_len} crc_or_parse_fail={crc_or_parse_fail} "
                        f"seq_gap_events={seq_gap_events} seq_missing={seq_missing}\n"
                    )
                    sys.stderr.flush()
                    last_stat_ts = time.time()
                continue
            buf.extend(chunk)

            while True:
                if _STOP_REQUESTED:
                    return

                sync_index = buf.find(SYNC_BYTES)
                if sync_index < 0:
                    # Keep last byte in case it's 0xAA
                    if len(buf) > 1:
                        del buf[:-1]
                    break

                if sync_index > 0:
                    del buf[:sync_index]

                # Need at least SYNC(2) + TOTAL_LEN(2)
                if len(buf) < 4:
                    break

                total_len = (buf[2] << 8) | buf[3]

                # TOTAL_LEN is the full frame length
                if total_len < 12 or total_len > MAX_TOTAL_LEN:
                    bad_len += 1
                    del buf[:1]
                    continue

                if len(buf) < total_len:
                    break

                frame = bytes(buf[:total_len])

                ok, ts_us, direction, seq, packet_data = parse_tlv_frame_and_validate(frame)
                if not ok:
                    crc_or_parse_fail += 1
                    # Drop 1 byte and resync
                    del buf[:1]
                    continue

                # Consume full frame on success
                del buf[:total_len]
                ok_frames += 1

                if seq is not None:
                    if last_seq is not None:
                        expected = (last_seq + 1) & 0xFFFFFFFF
                        if seq != expected:
                            seq_gap_events += 1
                            # Best-effort missing count without wrap handling
                            if seq > last_seq:
                                miss = seq - last_seq - 1
                                if miss > 0:
                                    seq_missing += miss
                    last_seq = seq

                if ts_us is None:
                    ts_us = int(time.time() * 1_000_000)

                if packet_data:
                    try:
                        write_pcap_packet(fifo, ts_us, packet_data)
                    except BrokenPipeError:
                        return
                    except OSError as exc:
                        if exc.errno == errno.EPIPE:
                            return
                        raise

            if STATS_ENABLED and (time.time() - last_stat_ts) >= 5:
                sys.stderr.write(
                    f"[STATS] ok={ok_frames} bad_len={bad_len} crc_or_parse_fail={crc_or_parse_fail} "
                    f"seq_gap_events={seq_gap_events} seq_missing={seq_missing}\n"
                )
                sys.stderr.flush()
                last_stat_ts = time.time()

        except BrokenPipeError:
            break
        except OSError as exc:
            if exc.errno == errno.EPIPE:
                break
            if os.name == "nt" and not _fifo_consumer_alive(fifo):
                break
            sys.stderr.write(f"[ERROR] {exc}\n")
            sys.stderr.flush()
            time.sleep(0.5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            # In lỗi ra stderr để không phá FIFO
            sys.stderr.write(f"[ERROR] {e}\n")
            sys.stderr.flush()
            time.sleep(0.5)


# ==========================
# Capture entry
# ==========================

def run_capture(fifo_path, serial_dev, baudrate):
    if serial is None:
        sys.stderr.write("pyserial not installed. Run: pip install pyserial\n")
        return 1

    _install_signal_handlers()

    fifo = None
    ser = None

    try:
        # Mở FIFO để ghi PCAP cho Wireshark
        fifo_fd = os.open(fifo_path, os.O_WRONLY)
        fifo = os.fdopen(fifo_fd, "wb", buffering=0)

        write_pcap_global_header(fifo)

        # Mở serial
        ser = serial.Serial(
            port=serial_dev,
            baudrate=baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.5,
        )

        read_frames_from_serial(ser, fifo)
    except (OSError, serial.SerialException) as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        return 1
    finally:
        if ser:
            try:
                if hasattr(ser, "cancel_read"):
                    ser.cancel_read()
                if hasattr(ser, "cancel_write"):
                    ser.cancel_write()
            except Exception:
                pass
            try:
                ser.close()
            except Exception:
                pass
        if fifo:
            fifo.close()

    return 0


# ==========================
# main / arg parsing
# ==========================

def main():
    args = sys.argv[1:]

    if "--extcap-interfaces" in args:
        print_interfaces()
        return 0

    if "--extcap-dlts" in args:
        print_dlts()
        return 0

    if "--extcap-config" in args:
        print_config()
        return 0

    if "--capture" in args:
        # Parse các tham số cần thiết
        interface = None
        fifo = None
        serial_dev = None
        baudrate = 115200

        it = iter(args)
        for a in it:
            if a == "--extcap-interface":
                interface = next(it, None)
            elif a == "--fifo":
                fifo = next(it, None)
            elif a == "--serial":
                serial_dev = next(it, None)
            elif a == "--baud":
                try:
                    baudrate = int(next(it, "115200"))
                except ValueError:
                    baudrate = 115200
            elif a == "--capture":
                # cờ, không có giá trị
                pass
            else:
                # Bỏ qua các option khác (filter, debug, ...)
                pass

        if interface != EXTCAP_INTERFACE_NAME:
            sys.stderr.write("Unknown interface\n")
            return 1
        if not fifo or not serial_dev:
            sys.stderr.write("Missing --fifo or --serial\n")
            return 1

        return run_capture(fifo, serial_dev, baudrate)

    # Nếu không rơi vào case nào trên, in help đơn giản
    sys.stderr.write(
        "This is an extcap binary for Wireshark.\n"
        "Use with Wireshark via --extcap-interfaces/--extcap-config/--capture.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
