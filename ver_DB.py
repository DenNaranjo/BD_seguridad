import sqlite3

DB = "empresa.db"
tablas = ["usuarios", "clientes", "productos", "logs_acceso"]

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
cur = con.cursor()

for tabla in tablas:
    print(f"\n{'='*50}")
    print(f"  TABLA: {tabla}")
    print('='*50)
    cur.execute(f"SELECT * FROM {tabla}")
    filas = cur.fetchall()
    if filas:
        print("  |  ".join(filas[0].keys()))
        print("-" * 50)
        for f in filas:
            print("  |  ".join(str(v) for v in tuple(f)))
    else:
        print("  (sin registros)")

con.close()