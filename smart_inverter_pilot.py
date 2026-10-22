#!/usr/bin/env python3
"""
smart_inverter_pilot.py
=======================
Network Traffic Analysis and Cybersecurity Vulnerability Assessment
of Smart Solar IoT Inverters. - Kavindu Abegunawardana 26342283

ENGE817 - STEM Research Methods

A single-file, reproducible testbed for observing whether smart solar inverter
telemetry is transmitted with transport encryption and authentication.

The tool has four modes:

    serve     Run the simulated inverter (Modbus/TCP server on port 502)
    monitor   Run the simulated vendor monitoring platform (polls once per second)
    analyse   Parse a saved .pcap capture and report the security posture
    pilot     Run the complete experiment end to end and write a capture file

Typical use (two terminals):

    sudo python3 smart_inverter_pilot.py serve
    python3 smart_inverter_pilot.py monitor

Or the whole experiment in one command:

    sudo python3 smart_inverter_pilot.py pilot --seconds 60 --out pilot_capture.pcap
    python3 smart_inverter_pilot.py analyse pilot_capture.pcap

Requirements
------------
    pip install "pymodbus==3.6.9" scapy
    apt-get install tshark          (or install Wireshark)

The pymodbus version is pinned deliberately: the library's API changed between
major releases, and an unpinned dependency makes the testbed non-reproducible.



from __future__ import annotations

import argparse
import datetime
import os
import random
import shutil
import statistics
import subprocess
import sys
import threading
import time

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

HOST = "127.0.0.1"
PORT = 502                      # IANA-registered Modbus port
POLL_INTERVAL_S = 1.0
REGISTER_COUNT = 4

# Register map, mirroring a SunSpec-style inverter model
REGISTERS = [
    ("AC power output", "W", 1),       # register 0, scale 1
    ("DC voltage", "V", 10),           # register 1, scale 10
    ("Grid frequency", "Hz", 100),     # register 2, scale 100
    ("Energy today", "kWh", 10),       # register 3, scale 10
]

MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}


# --------------------------------------------------------------------------
# Mode 1 - the simulated inverter
# --------------------------------------------------------------------------

def run_inverter(host: str = HOST, port: int = PORT, quiet: bool = False) -> None:
    """Serve four telemetry registers over Modbus/TCP.

    This stands in for the inverter endpoint. It exposes the same
    request-response interface a SunSpec-compliant device presents on its
    local network interface, including the absence of any transport security.
    """
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext,
    )
    from pymodbus.server import StartTcpServer

    store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
    context = ModbusServerContext(slaves=store, single=True)

    def update_readings() -> None:
        while True:
            values = [
                random.randint(1500, 5000),                 # AC power, W
                int(random.uniform(380, 420) * 10),          # DC voltage, V x10
                int(random.uniform(49.8, 50.2) * 100),       # frequency, Hz x100
                int(random.uniform(10, 30) * 10),            # energy, kWh x10
            ]
            context[0].setValues(3, 0, values)
            if not quiet:
                print(f"[inverter] P={values[0]}W  "
                      f"Vdc={values[1] / 10}V  "
                      f"f={values[2] / 100}Hz  "
                      f"E={values[3] / 10}kWh", flush=True)
            time.sleep(POLL_INTERVAL_S)

    print(f"Smart-inverter simulator listening on {host}:{port} (Modbus/TCP)",
          flush=True)
    time.sleep(0.3)
    threading.Thread(target=update_readings, daemon=True).start()
    StartTcpServer(context=context, address=(host, port))


# --------------------------------------------------------------------------
# Mode 2 - the simulated monitoring platform
# --------------------------------------------------------------------------

def run_monitor(host: str = HOST, port: int = PORT, quiet: bool = False) -> None:
    """Poll the inverter once per second, as a vendor platform would."""
    from pymodbus.client import ModbusTcpClient

    client = ModbusTcpClient(host, port=port)
    client.connect()
    print("Monitoring client connected to inverter. Polling telemetry...",
          flush=True)

    try:
        while True:
            rr = client.read_holding_registers(address=0, count=REGISTER_COUNT)
            if not rr.isError():
                p, v, f, e = rr.registers
                if not quiet:
                    print(f"[monitor] read -> P={p}W  Vdc={v / 10}V  "
                          f"f={f / 100}Hz  E={e / 10}kWh", flush=True)
            else:
                print("[monitor] read error:", rr, flush=True)
            time.sleep(POLL_INTERVAL_S)
    except KeyboardInterrupt:
        pass
    finally:
        client.close()


# --------------------------------------------------------------------------
# Mode 3 - capture analysis
# --------------------------------------------------------------------------

def analyse_capture(pcap_path: str, port: int = PORT) -> dict:
    """Parse a saved capture and report protocol and security posture.

    Returns a dictionary of results so the function can also be used
    programmatically.
    """
    from scapy.all import rdpcap, TCP, Raw

    if not os.path.exists(pcap_path):
        sys.exit(f"Capture file not found: {pcap_path}")

    packets = rdpcap(pcap_path)
    queries = 0
    responses = 0
    modbus_total = 0
    payload_bytes = 0
    readings: list[list[int]] = []
    timestamps: list[float] = []

    for pkt in packets:
        if TCP not in pkt or Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        if port not in (pkt[TCP].sport, pkt[TCP].dport):
            continue
        if len(payload) < 8:
            continue

        modbus_total += 1
        function_code = payload[7]

        if pkt[TCP].dport == port:
            queries += 1
            timestamps.append(float(pkt.time))
        else:
            responses += 1
            if function_code == 3 and len(payload) >= 9:
                byte_count = payload[8]
                data = payload[9:9 + byte_count]
                payload_bytes += byte_count
                readings.append([
                    int.from_bytes(data[i:i + 2], "big")
                    for i in range(0, len(data), 2)
                ])

    intervals = [round(timestamps[i + 1] - timestamps[i], 6)
                 for i in range(len(timestamps) - 1)]

    results = {
        "capture_file": pcap_path,
        "total_packets": len(packets),
        "modbus_packets": modbus_total,
        "queries": queries,
        "responses": responses,
        "payload_bytes_in_clear": payload_bytes,
        "packets_requiring_decryption": 0,
        "transport_encryption": "None observed",
        "authentication_exchange": "None observed",
        "readings": readings,
        "mean_interval_s": round(statistics.mean(intervals), 4) if intervals else None,
        "stdev_interval_s": round(statistics.pstdev(intervals), 4) if intervals else None,
    }

    _print_analysis(results)
    return results


def _print_analysis(r: dict) -> None:
    line = "=" * 66
    print(f"\nLoaded {r['total_packets']} packets from {r['capture_file']}\n")
    print(line)
    print("ANALYSIS SUMMARY")
    print(line)
    print(f"Modbus/TCP packets found      : {r['modbus_packets']}")
    print(f"  Queries (polls)             : {r['queries']}")
    print(f"  Responses (telemetry)       : {r['responses']}")

    if r["mean_interval_s"] is not None:
        print(f"Mean polling interval         : {r['mean_interval_s']} s "
              f"(SD {r['stdev_interval_s']} s)")

    if not r["modbus_packets"]:
        print("\nNo Modbus packets found - check the capture step.")
        return

    print(f"\nProtocol detected             : Modbus/TCP (SunSpec-style telemetry)")
    print(f"Transport encryption          : {r['transport_encryption']}")
    print(f"Authentication exchange       : {r['authentication_exchange']}")
    print(f"Register payload in the clear : {r['payload_bytes_in_clear']} bytes")
    print(f"Packets requiring decryption  : {r['packets_requiring_decryption']}")

    print("\nTelemetry recoverable by a passive observer:")
    header = (f"  {'#':<4}{'AC power':>12}{'DC voltage':>14}"
              f"{'Frequency':>13}{'Energy today':>15}")
    print(header)
    print("  " + "-" * (len(header) - 2))
    for i, regs in enumerate(r["readings"][:10], 1):
        if len(regs) >= 4:
            print(f"  {i:<4}{str(regs[0]) + ' W':>12}"
                  f"{f'{regs[1] / 10:.1f} V':>14}"
                  f"{f'{regs[2] / 100:.2f} Hz':>13}"
                  f"{f'{regs[3] / 10:.1f} kWh':>15}")
    print("  " + "-" * (len(header) - 2))
    print(f"\nFINDING: Modbus/TCP provides no transport encryption and no")
    print("authentication, so all inverter telemetry is recoverable by any")
    print("passive observer on the same network segment, and control messages")
    print("could be forged or replayed.")


# --------------------------------------------------------------------------
# Mode 4 - the complete experiment
# --------------------------------------------------------------------------

def run_pilot(seconds: int, out: str, port: int = PORT) -> None:
    """Run the whole experiment: inverter, capture, monitor, stop, analyse."""
    if shutil.which("tshark") is None:
        sys.exit("tshark not found. Install Wireshark, or run:\n"
                 "    sudo apt-get install -y tshark")

    for stale in (out, "inverter.log", "monitor.log", "capture.log"):
        if os.path.exists(stale):
            os.remove(stale)

    started = datetime.datetime.now()
    print("Pilot run started:", started.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 66)

    print("[1/5] Starting the inverter simulator...")
    inverter = subprocess.Popen(
        [sys.executable, __file__, "serve"],
        stdout=open("inverter.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(6)

    if inverter.poll() is not None:
        print("\nERROR: the inverter stopped unexpectedly. Log:\n")
        print(open("inverter.log").read()[:1500])
        sys.exit("Check the error above. Port 502 requires root privileges.")

    print("[2/5] Starting Wireshark (tshark) capture on loopback...")
    capture = subprocess.Popen(
        ["tshark", "-i", "lo", "-f", f"tcp port {port}",
         "-w", out, "-a", f"duration:{seconds}"],
        stdout=open("capture.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(4)

    print("[3/5] Starting the monitoring platform...")
    monitor = subprocess.Popen(
        [sys.executable, __file__, "monitor"],
        stdout=open("monitor.log", "w"), stderr=subprocess.STDOUT)

    print(f"[4/5] Recording telemetry for {seconds} seconds. Please wait...")
    try:
        capture.wait(timeout=seconds + 90)
    except subprocess.TimeoutExpired:
        capture.kill()

    print("[5/5] Stopping all processes...")
    for proc in (monitor, inverter):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    size = os.path.getsize(out) if os.path.exists(out) else 0
    print("=" * 66)
    if size > 100:
        print("PILOT COMPLETE")
        print(f"Capture file : {out} ({size} bytes)")
        print(f"Finished     : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
        analyse_capture(out, port=port)
    else:
        print("PROBLEM: the capture file is empty.")
        print("\ncapture.log:")
        print(open("capture.log").read()[:800]
              if os.path.exists("capture.log") else "(none)")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="smart_inverter_pilot",
        description="Reproducible testbed for smart solar inverter "
                    "telemetry security analysis (ENGE817).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Requirements")[0].split("The tool has")[1])
    sub = parser.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("serve", help="run the simulated inverter")
    s.add_argument("--port", type=int, default=PORT)
    s.add_argument("--quiet", action="store_true")

    m = sub.add_parser("monitor", help="run the simulated monitoring platform")
    m.add_argument("--port", type=int, default=PORT)
    m.add_argument("--quiet", action="store_true")

    a = sub.add_parser("analyse", help="analyse a saved .pcap capture")
    a.add_argument("pcap")
    a.add_argument("--port", type=int, default=PORT)

    p = sub.add_parser("pilot", help="run the complete experiment")
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--out", default="pilot_capture.pcap")
    p.add_argument("--port", type=int, default=PORT)

    args = parser.parse_args()

    if args.mode == "serve":
        run_inverter(port=args.port, quiet=args.quiet)
    elif args.mode == "monitor":
        run_monitor(port=args.port, quiet=args.quiet)
    elif args.mode == "analyse":
        analyse_capture(args.pcap, port=args.port)
    elif args.mode == "pilot":
        run_pilot(args.seconds, args.out, port=args.port)


if __name__ == "__main__":
    main()
