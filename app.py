"""
Servidor Flask con Base de Datos SQLite Segura
Tablas: usuarios, clientes, productos, logs_acceso
Medidas implementadas:
  1. Prevencion de SQL Injection (consultas parametrizadas)
  2. Hashing de contrasenas (bcrypt)
  3. Rate Limiting (limitar intentos de login)
"""

from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import time
from collections import defaultdict
from functools import wraps
import os

app = Flask(__name__)

# ----------------------------------------------------------
# MEDIDA 3: Rate Limiting
# ----------------------------------------------------------
failed_attempts = defaultdict(list)  # {ip: [timestamp, ...]}
MAX_INTENTOS   = 5
VENTANA_TIEMPO = 60

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip    = request.remote_addr
        ahora = time.time()
        failed_attempts[ip] = [t for t in failed_attempts[ip] if ahora - t < VENTANA_TIEMPO]
        if len(failed_attempts[ip]) >= MAX_INTENTOS:
            tiempo_restante = int(VENTANA_TIEMPO - (ahora - failed_attempts[ip][0]))
            return jsonify({
                "error": "Demasiados intentos fallidos.",
                "espera_segundos": tiempo_restante
            }), 429
        return f(*args, **kwargs)
    return decorated

# ----------------------------------------------------------
# Base de Datos
# ----------------------------------------------------------
DB_PATH = "empresa.db"

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # Tabla 1: Usuarios del sistema
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            email    TEXT    NOT NULL,
            rol      TEXT    NOT NULL DEFAULT 'user'
        )
    """)

    # Tabla 2: Clientes con datos sensibles
    cur.execute("""
        CREATE TABLE IF NOT EXISTS clientes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre          TEXT    NOT NULL,
            email           TEXT    NOT NULL UNIQUE,
            telefono        TEXT,
            direccion       TEXT,
            num_tarjeta     TEXT    NOT NULL,
            tipo_tarjeta    TEXT    NOT NULL,
            fecha_registro  TEXT    NOT NULL
        )
    """)

    # Tabla 3: Inventario de productos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS productos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre      TEXT    NOT NULL,
            categoria   TEXT    NOT NULL,
            precio      REAL    NOT NULL,
            stock       INTEGER NOT NULL DEFAULT 0,
            proveedor   TEXT
        )
    """)

    # Tabla 4: Logs de acceso
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs_acceso (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            ip        TEXT    NOT NULL,
            endpoint  TEXT    NOT NULL,
            username  TEXT,
            resultado TEXT    NOT NULL
        )
    """)

    con.commit()

    # Datos de prueba - usuarios
    admin_hash = bcrypt.hashpw(b"Admin1234!", bcrypt.gensalt()).decode()
    try:
        cur.execute(
            "INSERT INTO usuarios (username, password, email, rol) VALUES (?, ?, ?, ?)",
            ("admin", admin_hash, "admin@empresa.com", "admin")
        )
    except sqlite3.IntegrityError:
        pass

    user_hash = bcrypt.hashpw(b"User5678!", bcrypt.gensalt()).decode()
    try:
        cur.execute(
            "INSERT INTO usuarios (username, password, email, rol) VALUES (?, ?, ?, ?)",
            ("juan", user_hash, "juan@empresa.com", "user")
        )
    except sqlite3.IntegrityError:
        pass

    # Datos de prueba - clientes
    clientes_demo = [
        ("Maria Lopez",  "maria@gmail.com",   "555-1001", "Av. Reforma 10",   "**** **** **** 4321", "Visa",       "2024-01-15"),
        ("Carlos Perez", "carlos@hotmail.com","555-2002", "Calle 5 de Mayo",  "**** **** **** 8765", "Mastercard", "2024-03-22"),
        ("Ana Torres",   "ana@yahoo.com",     "555-3003", "Blvd. Hidalgo 7",  "**** **** **** 1122", "Visa",       "2024-06-10"),
    ]
    for c in clientes_demo:
        try:
            cur.execute(
                "INSERT INTO clientes (nombre,email,telefono,direccion,num_tarjeta,tipo_tarjeta,fecha_registro) VALUES (?,?,?,?,?,?,?)", c
            )
        except sqlite3.IntegrityError:
            pass

    # Datos de prueba - productos
    productos_demo = [
        ("Laptop ProMax",    "Electronica", 18999.99, 15, "TechSupply SA"),
        ("Mouse Inalambrico","Perifericos",   499.00, 80, "Accesorios MX"),
        ("Teclado Mecanico", "Perifericos",  1299.50, 45, "Accesorios MX"),
        ("Monitor 27 pulgadas","Electronica",6500.00, 10, "TechSupply SA"),
        ("Silla Ergonomica", "Mobiliario",   3200.00, 20, "OfiMuebles"),
    ]
    for p in productos_demo:
        try:
            cur.execute(
                "INSERT INTO productos (nombre,categoria,precio,stock,proveedor) VALUES (?,?,?,?,?)", p
            )
        except sqlite3.IntegrityError:
            pass

    con.commit()
    con.close()

# ----------------------------------------------------------
# Funcion auxiliar para registrar logs
# ----------------------------------------------------------
def registrar_log(ip, endpoint, resultado, username=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO logs_acceso (timestamp, ip, endpoint, username, resultado) VALUES (?,?,?,?,?)",
        (ts, ip, endpoint, username, resultado)
    )
    con.commit()
    con.close()

# ----------------------------------------------------------
# RUTAS - Usuarios
# ----------------------------------------------------------

@app.route("/")
def index():
    return jsonify({
        "mensaje": "Servidor seguro activo.",
        "endpoints": ["/registro", "/login", "/buscar", "/clientes", "/productos", "/logs"]
    })


@app.route("/registro", methods=["POST"])
def registro():
    datos = request.get_json()
    if not datos:
        return jsonify({"error": "Se esperaba JSON"}), 400
    username = datos.get("username", "").strip()
    password = datos.get("password", "")
    email    = datos.get("email", "").strip()
    if not username or not password or not email:
        return jsonify({"error": "Faltan campos: username, password, email"}), 400

    # MEDIDA 2: Hash con bcrypt
    hash_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # MEDIDA 1: Consulta parametrizada
        cur.execute(
            "INSERT INTO usuarios (username, password, email) VALUES (?, ?, ?)",
            (username, hash_pass, email)
        )
        con.commit()
        con.close()
        return jsonify({"mensaje": f"Usuario '{username}' registrado correctamente."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "El nombre de usuario ya existe."}), 409


@app.route("/login", methods=["POST"])
@rate_limit  # MEDIDA 3
def login():
    datos = request.get_json()
    if not datos:
        return jsonify({"error": "Se esperaba JSON"}), 400
    username = datos.get("username", "").strip()
    password = datos.get("password", "")
    ip       = request.remote_addr
    if not username or not password:
        return jsonify({"error": "Faltan campos: username, password"}), 400

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # MEDIDA 1: Consulta parametrizada
    cur.execute("SELECT password, rol FROM usuarios WHERE username = ?", (username,))
    fila = cur.fetchone()
    con.close()

    if fila is None:
        failed_attempts[ip].append(time.time())
        registrar_log(ip, "/login", "fallido", username)
        return jsonify({"error": "Credenciales invalidas."}), 401

    # MEDIDA 2: Verificar hash bcrypt
    if bcrypt.checkpw(password.encode(), fila[0].encode()):
        failed_attempts[ip] = []
        registrar_log(ip, "/login", "exitoso", username)
        return jsonify({"mensaje": "Login exitoso.", "rol": fila[1]}), 200
    else:
        failed_attempts[ip].append(time.time())
        registrar_log(ip, "/login", "fallido", username)
        return jsonify({"error": "Credenciales invalidas."}), 401


@app.route("/buscar", methods=["GET"])
def buscar():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Parametro 'q' requerido."}), 400
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    # MEDIDA 1: Consulta parametrizada con LIKE
    cur.execute(
        "SELECT id, username, email, rol FROM usuarios WHERE username LIKE ?",
        (f"%{q}%",)
    )
    resultado = [dict(f) for f in cur.fetchall()]
    con.close()
    return jsonify(resultado), 200


# ----------------------------------------------------------
# RUTAS - Clientes
# ----------------------------------------------------------

@app.route("/clientes", methods=["GET"])
def listar_clientes():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT id, nombre, email, telefono, tipo_tarjeta, num_tarjeta, fecha_registro FROM clientes")
    resultado = [dict(f) for f in cur.fetchall()]
    con.close()
    return jsonify(resultado), 200


@app.route("/clientes", methods=["POST"])
def agregar_cliente():
    datos = request.get_json()
    if not datos:
        return jsonify({"error": "Se esperaba JSON"}), 400
    for c in ["nombre", "email", "telefono", "direccion", "num_tarjeta", "tipo_tarjeta"]:
        if not datos.get(c):
            return jsonify({"error": f"Falta el campo: {c}"}), 400

    # Enmascarar numero de tarjeta: solo guardar ultimos 4 digitos
    tarjeta_raw  = datos["num_tarjeta"].replace(" ", "").replace("-", "")
    tarjeta_mask = f"**** **** **** {tarjeta_raw[-4:]}"
    fecha_hoy    = time.strftime("%Y-%m-%d")

    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # MEDIDA 1: Consulta parametrizada
        cur.execute(
            "INSERT INTO clientes (nombre,email,telefono,direccion,num_tarjeta,tipo_tarjeta,fecha_registro) VALUES (?,?,?,?,?,?,?)",
            (datos["nombre"], datos["email"], datos["telefono"], datos["direccion"],
             tarjeta_mask, datos["tipo_tarjeta"], fecha_hoy)
        )
        con.commit()
        con.close()
        return jsonify({"mensaje": "Cliente registrado correctamente."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "El email del cliente ya existe."}), 409


# ----------------------------------------------------------
# RUTAS - Productos
# ----------------------------------------------------------

@app.route("/productos", methods=["GET"])
def listar_productos():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM productos")
    resultado = [dict(f) for f in cur.fetchall()]
    con.close()
    return jsonify(resultado), 200


@app.route("/productos", methods=["POST"])
def agregar_producto():
    datos = request.get_json()
    if not datos:
        return jsonify({"error": "Se esperaba JSON"}), 400
    for c in ["nombre", "categoria", "precio", "stock"]:
        if datos.get(c) is None:
            return jsonify({"error": f"Falta el campo: {c}"}), 400
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # MEDIDA 1: Consulta parametrizada
        cur.execute(
            "INSERT INTO productos (nombre,categoria,precio,stock,proveedor) VALUES (?,?,?,?,?)",
            (datos["nombre"], datos["categoria"], float(datos["precio"]),
             int(datos["stock"]), datos.get("proveedor", ""))
        )
        con.commit()
        con.close()
        return jsonify({"mensaje": "Producto agregado correctamente."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------------------------------------------------
# RUTAS - Logs
# ----------------------------------------------------------

@app.route("/logs", methods=["GET"])
def ver_logs():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM logs_acceso ORDER BY id DESC LIMIT 50")
    resultado = [dict(f) for f in cur.fetchall()]
    con.close()
    return jsonify(resultado), 200


# ----------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print("  Servidor de seguridad iniciado en http://127.0.0.1:5000")
    print("  Base de datos: empresa.db")
    print("  Tablas: usuarios, clientes, productos, logs_acceso")
    print("  Medidas activas:")
    print("    [OK] SQL Injection  -> consultas parametrizadas")
    print("    [OK] Hashing        -> bcrypt (salt automatico)")
    print(f"    [OK] Rate Limiting  -> max {MAX_INTENTOS} intentos / {VENTANA_TIEMPO}s por IP")
    print("=" * 55)
    app.run(debug=False, host="127.0.0.1", port=5000)