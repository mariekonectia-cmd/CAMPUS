from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from datetime import timedelta
from functools import wraps
import requests
import random


#Cargar variables de entorno desde archivo .env
load_dotenv()

# Intentar importar pokebase si está instalado
try:
    import pokebase as pb
except Exception:
    pb = None
app = Flask(__name__)
# Cargar clave secreta desde .env para seguridad en producción
app.secret_key = os.getenv("SECRET_KEY", "tu_clave_secreta_aqui")

# Configuración de sesiones: duración por defecto cuando el usuario marque 'recordarme'
app.permanent_session_lifetime = timedelta(days=7)
# Cookies sólo HTTP (evita acceso desde JS). En producción, ponga SESSION_COOKIE_SECURE = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

def conectarCampus():
    conexion = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    return conexion


def get_table_columns(conn, table_name):
    cur = conn.cursor()
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s", (table_name,))
    cols = [r[0] for r in cur.fetchall()]
    cur.close()
    return cols


@app.route("/")
def hello_world():
    pokemons = []
    try:
        # Obtener la lista completa y elegir 20 al azar
        resp = requests.get('https://pokeapi.co/api/v2/pokemon?limit=100000', timeout=8)
        resp.raise_for_status()
        data = resp.json()
        results = data.get('results', []) or []
        count = min(20, len(results))
        sampled = random.sample(results, count) if results else []
        for item in sampled:
            name = item.get('name', '').title()
            url = item.get('url', '')
            pid = None
            try:
                pid = int(url.rstrip('/').split('/')[-1])
            except Exception:
                pid = None

            sprite = None
            if pid:
                sprite = f"https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/{pid}.png"

            pokemons.append({'id': pid, 'name': name, 'sprite': sprite})
    except Exception as e:
        print(f"Error fetching pokemon list: {e}")

    return render_template("base.html", pokemons=pokemons)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    
    if request.method == "POST":
        usuario = (request.form.get("id_usuarios") or request.form.get("user") or "").strip()
        password = request.form.get("password", "").strip()

        if not usuario or not password:
            error = "Usuario y contraseña son requeridos"
            return render_template("login.html", error=error)

        try:
            conn = conectarCampus()
            cursor = conn.cursor()
            
            # Verificar si el usuario existe (case-insensitive)
            cursor.execute("SELECT password, user_email FROM users WHERE LOWER(user_name) = LOWER(%s)", (usuario,))
            fila = cursor.fetchone()
            
            if fila:
                # El usuario ya existe
                password_guardada, email_guardado = fila
                if check_password_hash(password_guardada, password):
                    # Usuario existe con contraseña correcta
                    remember = True if request.form.get('remember') == 'on' else False
                    session['id_usuarios'] = usuario
                    session['user_email'] = email_guardado
                    # Si el usuario marcó 'recordarme', hacer la sesión permanente
                    session.permanent = remember
                    cursor.close()
                    conn.close()
                    return redirect(url_for('bienvenida'))
                else:
                    cursor.close()
                    conn.close()
                    error = "Usuario existe pero la contraseña es incorrecta"
                    return render_template("login.html", error=error)
            else:
                # Usuario no existe
                cursor.close()
                conn.close()
                error = "Usuario no existe"
                session['usuario_intento'] = usuario
                return redirect(url_for('registro', error=error))
        
        except Exception as e:
            error = f"Error: {str(e)}"
            print(f"Error en login: {str(e)}")
            return render_template("login.html", error=error)

    return render_template("login.html", error=error)

@app.route("/registro", methods=["GET", "POST"])
def registro():
    error = None
    mensaje = None
    
    if request.method == "POST":
        # Soportar tanto los nombres antiguos como los nuevos en la plantilla
        usuario = (request.form.get("user_name") or request.form.get("user") or "").strip()
        password = request.form.get("password", "").strip()
        password_confirm = request.form.get("password-confirm", "").strip()
        email = (request.form.get("user_email") or request.form.get("email") or "").strip()

        if not usuario or not password or not password_confirm or not email:
            error = "Todos los campos son requeridos"
            return render_template("registro.html", error=error)

        if password != password_confirm:
            error = "Las contraseñas no coinciden"
            return render_template("registro.html", error=error)

        if len(password) < 6:
            error = "La contraseña debe tener al menos 6 caracteres"
            return render_template("registro.html", error=error)

        try:
            conn = conectarCampus()
            cursor = conn.cursor()
            
            # Verificar si el usuario ya existe (case-insensitive)
            cursor.execute("SELECT 1 FROM users WHERE LOWER(user_name) = LOWER(%s)", (usuario,))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                error = "El nombre de usuario ya está en uso"
                return render_template("registro.html", error=error)
            
            # Verificar si el email ya está registrado
            cursor.execute("SELECT 1 FROM users WHERE user_email = %s", (email,))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                error = "El email ya está registrado"
                return render_template("registro.html", error=error)

            # Registrar nuevo usuario
            password_hasheada = generate_password_hash(password)

            # Construir INSERT dinámico según columnas existentes
            cols = get_table_columns(conn, 'users')
            insert_fields = ['user_name', 'password', 'user_email']
            insert_values = [usuario, password_hasheada, email]

            # Si existe columna 'rol' (no nula), asignar un rol por defecto
            if 'rol' in cols:
                # Intentar obtener el tipo enum asociado a la columna y su primer valor
                cursor.execute("SELECT udt_name FROM information_schema.columns WHERE table_name = %s AND column_name = %s", ('users', 'rol'))
                udt_row = cursor.fetchone()
                default_role = None
                if udt_row and udt_row[0]:
                    udt_name = udt_row[0]
                    # Leer labels del enum desde pg_catalog
                    cursor.execute("SELECT enumlabel FROM pg_enum JOIN pg_type ON pg_enum.enumtypid = pg_type.oid WHERE pg_type.typname = %s ORDER BY enumsortorder", (udt_name,))
                    enum_rows = cursor.fetchall()
                    if enum_rows:
                        default_role = enum_rows[0][0]

                # Fallback: si no encontramos un enum válido, usar 'usuario' si parece tener sentido
                if not default_role:
                    default_role = 'usuario'

                insert_fields.append('rol')
                insert_values.append(default_role)

            placeholders = ','.join(['%s'] * len(insert_values))
            sql = f"INSERT INTO users ({', '.join(insert_fields)}) VALUES ({placeholders})"
            cursor.execute(sql, tuple(insert_values))
            conn.commit()
            
            # Guardar en sesión después de registrar
            session['id_usuarios'] = usuario
            session['user_email'] = email
            
            print(f"Nuevo usuario registrado: {usuario}")
            cursor.close()
            conn.close()
            
            return redirect(url_for('bienvenida'))
        
        except Exception as e:
            error = f"Error al registrar: {str(e)}"
            print(f"Error en registro: {str(e)}")
            return render_template("registro.html", error=error)

    # Si viene de un login fallido, mostrar el mensaje
    if 'usuario_intento' in session:
        mensaje = "Usuario no existe. Por favor, regístrese para continuar"
        session.pop('usuario_intento', None)

    return render_template("registro.html", error=error, mensaje=mensaje)

@app.route("/bienvenida")
def bienvenida():
    if 'id_usuarios' not in session:
        return redirect(url_for('login'))
    # Extraer mensaje de error temporal (si existe)
    error = session.pop('error', None)
    return render_template("bienvenida.html", usuario=session['id_usuarios'], email=session.get('user_email'), error=error)

@app.route("/volver")
def volver():
    # Volver a inicio y limpiar sesión
    if 'id_usuarios' in session:
        session.clear()
    return redirect(url_for('hello_world'))


@app.route('/logout')
def logout():
    # Cerrar la sesión del usuario y redirigir al login
    session.clear()
    return redirect(url_for('login'))

@app.route("/completar-datos", methods=["POST"])
def completar_datos():
    if 'id_usuarios' not in session:
        return redirect(url_for('login'))

    nombre = request.form.get("nombre", "").strip()
    telefono = request.form.get("telefono", "").strip()
    ciudad = request.form.get("ciudad", "").strip()
    descripcion = request.form.get("descripcion", "").strip()

    try:
        conn = conectarCampus()
        cursor = conn.cursor()

        cols = get_table_columns(conn, 'users')

        # Validar que el teléfono no esté registrado por otro usuario (si la columna existe)
        if 'telefono' in cols and telefono:
            cursor.execute("SELECT 1 FROM users WHERE telefono = %s AND user_name != %s", (telefono, session['id_usuarios']))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                session['error'] = "El teléfono ya está registrado por otro usuario"
                return redirect(url_for('bienvenida'))

        # Validar que el nombre completo no esté ya en uso por otro usuario (si la columna existe)
        if 'nombre_completo' in cols and nombre:
            cursor.execute("SELECT 1 FROM users WHERE nombre_completo = %s AND user_name != %s", (nombre, session['id_usuarios']))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                session['error'] = "El nombre completo ya está registrado por otro usuario"
                return redirect(url_for('bienvenida'))

        # Construir UPDATE dinámico según columnas existentes
        field_map = {'nombre': 'nombre_completo', 'telefono': 'telefono', 'ciudad': 'ciudad', 'descripcion': 'descripcion'}
        form_values = {'nombre': nombre, 'telefono': telefono, 'ciudad': ciudad, 'descripcion': descripcion}
        updates = []
        values = []
        for form_field, col in field_map.items():
            val = form_values.get(form_field)
            if col in cols and val:
                updates.append(f"{col} = %s")
                values.append(val)

        if updates:
            values.append(session['id_usuarios'])
            sql_query = "UPDATE users SET " + ", ".join(updates) + " WHERE user_name = %s"
            cursor.execute(sql_query, tuple(values))
            conn.commit()

        cursor.close()
        conn.close()

        session.clear()
        return redirect(url_for('hello_world'))

    except Exception as e:
        print(f"Error: {str(e)}")
        return redirect(url_for('bienvenida'))

if __name__ == "__main__":
    app.run(debug=True)