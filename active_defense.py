#!/usr/bin/env python3
"""
Active Defense System - Custom IPS
Monitors Suricata alerts and automatically blocks malicious IPs using iptables.
"""

import json
import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ======================== CONFIGURATION ========================
SURICATA_LOG = "/var/log/suricata/eve.json"
DATABASE_PATH = "defense_log.db"
BLOCKED_IPS_FILE = "blocked_ips.txt"

# Lista de SIDs que dispararán el bloqueo automático
CRITICAL_SIDS = [1000001, 1000002, 1000003]  # Incluye tu SID de prueba

# ======================== DATABASE SETUP ========================
def init_database():
    """Inicializa la base de datos SQLite"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            alert_signature TEXT NOT NULL,
            action_taken TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()
    print(f"[+] Database initialized: {DATABASE_PATH}")

# ======================== LOGGING FUNCTION ========================
def log_incident(src_ip, alert_sig, action):
    """Registra un incidente en la base de datos SQLite"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("""
            INSERT INTO incidents (timestamp, src_ip, alert_signature, action_taken)
            VALUES (?, ?, ?, ?)
        """, (timestamp, src_ip, alert_sig, action))
        
        conn.commit()
        conn.close()
        print(f"[DB] Incident logged: {src_ip} | {alert_sig}")
        
    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")

# ======================== FIREWALL FUNCTIONS ========================
def is_ip_blocked(ip):
    """Verifica si una IP ya está bloqueada en iptables"""
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-v", "-n"],
            capture_output=True,
            text=True,
            check=True
        )
        return ip in result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to check iptables: {e}")
        return False

def block_ip(ip):
    """Bloquea una IP usando iptables"""
    # Evitar bloquear IPs locales o reservadas (comentamos esta validación para testing)
    # if ip.startswith(("127.", "192.168.", "10.", "172.")):
    #     print(f"[WARNING] Skipping local IP: {ip}")
    #     return False
    
    # Verificar si ya está bloqueada
    if is_ip_blocked(ip):
        print(f"[INFO] IP already blocked: {ip}")
        return False
    
    try:
        # Ejecutar comando iptables para bloquear (DROP)
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True
        )
        
        print(f"[FIREWALL] ✓ IP BLOCKED: {ip}")
        
        # Guardar IP en archivo de texto
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")
        return False

# ======================== LOG MONITORING ========================
def tail_follow(file_path):
    """Implementa funcionalidad 'tail -f' en Python"""
    with open(file_path, "r") as file:
        # Ir al final del archivo
        file.seek(0, 2)
        
        while True:
            line = file.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

def process_alert(alert_json):
    """Procesa una alerta de Suricata y decide si debe bloquearse"""
    try:
        # Verificar que es un evento de tipo alerta
        if alert_json.get("event_type") != "alert":
            return
        
        # Extraer información crítica
        src_ip = alert_json.get("src_ip", "UNKNOWN")
        alert_info = alert_json.get("alert", {})
        signature = alert_info.get("signature", "UNKNOWN")
        signature_id = alert_info.get("signature_id", 0)
        
        print(f"\n[ALERT] Detected: {signature}")
        print(f"        Source IP: {src_ip}")
        print(f"        SID: {signature_id}")
        
        # Decidir si bloquear basándonos en el SID
        if signature_id in CRITICAL_SIDS:
            print(f"[ACTION] Critical SID detected - Initiating block...")
            
            if block_ip(src_ip):
                log_incident(src_ip, signature, "IP_BLOCKED")
            else:
                log_incident(src_ip, signature, "BLOCK_FAILED")
        else:
            print(f"[INFO] Alert logged but not critical (SID: {signature_id})")
            log_incident(src_ip, signature, "ALERT_ONLY")
            
    except (KeyError, ValueError) as e:
        print(f"[ERROR] Failed to parse alert: {e}")

# ======================== MAIN EXECUTION ========================
def main():
    """Función principal"""
    print("="*60)
    print(" 🛡️  ACTIVE DEFENSE SYSTEM - STARTED")
    print("="*60)
    print(f"[*] Monitoring: {SURICATA_LOG}")
    print(f"[*] Database: {DATABASE_PATH}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    # Verificar que el archivo de log existe
    if not Path(SURICATA_LOG).exists():
        print(f"[ERROR] Log file not found: {SURICATA_LOG}")
        return
    
    # Inicializar base de datos
    init_database()
    
    try:
        # Monitorear el log en tiempo real
        for line in tail_follow(SURICATA_LOG):
            try:
                alert_data = json.loads(line)
                process_alert(alert_data)
            except json.JSONDecodeError:
                continue
                
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down Active Defense System...")
        print("[*] Goodbye!")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")

if __name__ == "__main__":
    main()