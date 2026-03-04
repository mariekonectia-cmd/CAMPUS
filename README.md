# CAMPUS

# 🎓 Campus Konectia - Plataforma de Gestión Académica

Este es un sistema de gestión escolar desarrollado con **Python** y  **Flask** , que permite la administración de usuarios, visualización de perfiles y gestión de calendarios.

## 🚀 Características principales

* **Sistema de Roles:** Acceso diferenciado para Usuarios y Administradores.
* **Panel de Administración:** Gestión completa de usuarios (Ver, Editar, Eliminar).
* **Seguridad:** Autenticación protegida y manejo de sesiones de usuario.
* **Base de Datos:** Integración con PostgreSQL para el almacenamiento persistente.
* **Interfaz Dinámica:** Plantillas responsivas usando Jinja2.

## 🛠️ Tecnologías utilizadas

* **Backend:** Python 3.x + Flask.
* **Base de Datos:** PostgreSQL + Psycopg2.
* **Frontend:** HTML5, CSS3 (Diseño con gradientes y componentes modernos).
* **Seguridad:** Werkzeug para el hasheo de contraseñas.

## 📋 Requisitos previos

Para ejecutar este proyecto localmente, necesitas tener instalado:

* Python 3.x
* PostgreSQL
* Un entorno virtual (venv)

## 🔧 Instalación y configuración

1. **Clonar el repositorio:**
   **Bash**

   ```
   git clone https://github.com/tu-usuario/campus-konectia.git
   cd campus-konectia
   ```
2. **Crear y activar el entorno virtual:**
   **Bash**

   ```
   python -m venv .venv
   # En Windows:
   .venv\Scripts\activate
   ```
3. **Instalar dependencias:**
   **Bash**

   ```
   pip install flask psycopg2 werkzeug
   ```
4. **Configurar la base de datos:**
   Asegúrate de tener una base de datos PostgreSQL llamada `campus_db` (o la que hayas definido en `conectarCampus()`) y ejecuta el script SQL para crear la tabla `users`.
5. **Ejecutar la aplicación:**
   **Bash**

   ```
   python app.py
   ```

   La aplicación estará disponible en `http://127.0.0.1:5000`.

## 📸 Vistas del Proyecto

* **Login:** Interfaz de acceso para usuarios y administradores.
* **Perfil Admin:** Panel de control con acceso a gestión de usuarios y calendario.
* **Gestión de Usuarios:** Tabla interactiva para administrar la base de datos de alumnos.

---

### ✨ Notas del desarrollador

Este proyecto fue diseñado para ser escalable. Actualmente incluye módulos de gestión de horarios y asignaturas en fase de desarrollo.
