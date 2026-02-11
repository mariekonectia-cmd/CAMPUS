from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from datetime import timedelta
from functools import wraps


#Cargar variables de entorno desde archivo .env
load_dotenv()

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


@app.route("/")
def hello_world():
    return render_template("base.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    
    if request.method == "POST":
        usuario = request.form.get("user", "").strip()
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
                    session['usuario'] = usuario
                    session['email'] = email_guardado
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
        usuario = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()
        password_confirm = request.form.get("password-confirm", "").strip()
        email = request.form.get("email", "").strip()

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
            cursor.execute("INSERT INTO users (user_name, password, user_email) VALUES (%s, %s, %s)",
                           (usuario, password_hasheada, email))
            conn.commit()
            
            # Guardar en sesión después de registrar
            session['usuario'] = usuario
            session['email'] = email
            
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
    if 'usuario' not in session:
        return redirect(url_for('login'))
    # Extraer mensaje de error temporal (si existe)
    error = session.pop('error', None)
    return render_template("bienvenida.html", usuario=session['usuario'], email=session['email'], error=error)

@app.route("/volver")
def volver():
    # Volver a inicio y limpiar sesión
    if 'usuario' in session:
        session.clear()
    return redirect(url_for('hello_world'))


@app.route('/logout')
def logout():
    # Cerrar la sesión del usuario y redirigir al login
    session.clear()
    return redirect(url_for('login'))

@app.route("/completar-datos", methods=["POST"])
def completar_datos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    nombre = request.form.get("nombre", "").strip()
    telefono = request.form.get("telefono", "").strip()
    ciudad = request.form.get("ciudad", "").strip()
    descripcion = request.form.get("descripcion", "").strip()
    
    try:
        conn = conectarCampus()
        cursor = conn.cursor()
        # Validar que el teléfono no esté registrado por otro usuario
        if telefono:
            cursor.execute("SELECT 1 FROM users WHERE telefono = %s AND user_name != %s", (telefono, session['usuario']))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                session['error'] = "El teléfono ya está registrado por otro usuario"
                return redirect(url_for('bienvenida'))

        # Validar que el nombre completo no esté ya en uso por otro usuario
        if nombre:
            cursor.execute("SELECT 1 FROM users WHERE nombre_completo = %s AND user_name != %s", (nombre, session['usuario']))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                session['error'] = "El nombre completo ya está registrado por otro usuario"
                return redirect(url_for('bienvenida'))

        cursor.execute("""UPDATE users SET nombre_completo = %s, telefono = %s, 
                         ciudad = %s, descripcion = %s WHERE user_name = %s""",
                       (nombre, telefono, ciudad, descripcion, session['usuario']))
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