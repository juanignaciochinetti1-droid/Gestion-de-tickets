import os
import secrets
import sqlite3
from collections import defaultdict
from datetime import datetime
from functools import wraps
from time import time

from flask import (Flask, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ── Clave secreta persistente ────────────────────────────────────────────────
# Se genera aleatoriamente en el primer arranque y se guarda en disco.
_KEY_FILE = os.path.join(DATA_DIR, '.flask_secret')
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE) as _f:
        _default_key = _f.read().strip()
else:
    _default_key = secrets.token_hex(32)
    with open(_KEY_FILE, 'w') as _f:
        _f.write(_default_key)

app.secret_key = os.environ.get('SECRET_KEY', _default_key)

csrf = CSRFProtect(app)

# ── Configuración de cookies de sesión ──────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JS no puede leer la cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protege contra CSRF cross-site

# En Docker se puede pasar DATA_DIR=/app/data para persistir DB y clave en un volumen.
DATA_DIR    = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
DATABASE    = os.path.join(DATA_DIR, 'tickets.db')
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ESTADOS = {
    'en_espera': 'En Espera',
    'en_proceso': 'En Proceso',
    'terminado': 'Terminado',
    'anulado': 'Anulado',
}

SECTORES = [
    'Administración',
    'Contabilidad',
    'Recursos Humanos',
    'Sistemas',
    'Ventas',
    'Depósito / Logística',
    'Producción',
    'Gerencia',
    'Otro',
]


# ── Base de datos ────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        # Evita "database is locked" cuando varios usuarios acceden a la vez
        db.execute('PRAGMA busy_timeout = 5000')
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        # WAL mejora el acceso concurrente (múltiples usuarios en red)
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS admin (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ticket (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre           TEXT    NOT NULL,
                sector           TEXT    NOT NULL,
                descripcion      TEXT    NOT NULL,
                imagen           TEXT,
                estado           TEXT    NOT NULL DEFAULT 'en_espera'
                                     CHECK(estado IN ('en_espera','en_proceso','terminado','anulado')),
                notas_admin      TEXT,
                fecha_creacion   TEXT    NOT NULL,
                fecha_actualizacion TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ticket_estado  ON ticket(estado);
            CREATE INDEX IF NOT EXISTS idx_ticket_sector  ON ticket(sector);
            CREATE INDEX IF NOT EXISTS idx_ticket_fecha   ON ticket(fecha_creacion);
        ''')
        admins_iniciales = [
            ('juan',    'juan1'),
            ('leandro', 'lean1'),
        ]
        for username, password in admins_iniciales:
            existe = db.execute('SELECT id FROM admin WHERE username = ?', (username,)).fetchone()
            if not existe:
                db.execute(
                    'INSERT INTO admin (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password))
                )
        db.commit()


# ── Helpers ──────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Verifica magic bytes del archivo para confirmar que es una imagen real.
# Evita que alguien suba un .exe/.php renombrado como .jpg.
def is_valid_image(file_storage):
    header = file_storage.read(16)
    file_storage.seek(0)
    return (
        header[:3]  == b'\xff\xd8\xff'         or  # JPEG / JPG
        header[:8]  == b'\x89PNG\r\n\x1a\n'    or  # PNG
        header[:6]  in (b'GIF87a', b'GIF89a')  or  # GIF
        (header[:4] == b'RIFF' and header[8:12] == b'WEBP')  # WebP
    )


# ── Rate limiting para login ─────────────────────────────────────────────────
_login_attempts: dict = defaultdict(list)
_MAX_INTENTOS   = 5
_LOCKOUT_SEG    = 300  # 5 minutos

def _ip_bloqueada(ip: str) -> bool:
    ahora = time()
    recientes = [t for t in _login_attempts[ip] if ahora - t < _LOCKOUT_SEG]
    _login_attempts[ip] = recientes
    return len(recientes) >= _MAX_INTENTOS

def _registrar_intento_fallido(ip: str) -> None:
    _login_attempts[ip].append(time())


# ── Cabeceras de seguridad HTTP ──────────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection']       = '1; mode=block'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    return response


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Debés iniciar sesión para acceder a esta sección.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── Rutas públicas ───────────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        sector = request.form.get('sector', '').strip()
        descripcion = request.form.get('descripcion', '').strip()

        errores = []
        if not nombre:
            errores.append('El nombre es obligatorio.')
        elif len(nombre) > 100:
            errores.append('El nombre no puede superar los 100 caracteres.')
        if not sector:
            errores.append('El sector es obligatorio.')
        if not descripcion:
            errores.append('La descripción del problema es obligatoria.')
        elif len(descripcion) > 2000:
            errores.append('La descripción no puede superar los 2000 caracteres.')
        if sector and sector not in SECTORES:
            errores.append('El sector seleccionado no es válido.')

        # Validar imagen ANTES de guardarla en disco
        archivo = request.files.get('imagen')
        imagen_nombre_seguro = None
        if archivo and archivo.filename:
            nombre_base = secure_filename(archivo.filename)
            if not nombre_base or not allowed_file(nombre_base):
                errores.append('Formato de imagen no válido. Usá PNG, JPG, GIF o WEBP.')
            elif not is_valid_image(archivo):
                errores.append('El archivo no es una imagen válida.')
            else:
                imagen_nombre_seguro = nombre_base

        if errores:
            for e in errores:
                flash(e, 'danger')
            return render_template('index.html', sectores=SECTORES,
                                   form_data=request.form)

        # Guardar imagen solo si toda la validación pasó
        imagen_nombre = None
        if imagen_nombre_seguro:
            imagen_nombre = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{imagen_nombre_seguro}"
            archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], imagen_nombre))

        ahora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db = get_db()
        db.execute(
            '''INSERT INTO ticket
               (nombre, sector, descripcion, imagen, estado, fecha_creacion, fecha_actualizacion)
               VALUES (?, ?, ?, ?, "en_espera", ?, ?)''',
            (nombre, sector, descripcion, imagen_nombre, ahora, ahora)
        )
        db.commit()
        flash('¡Tu solicitud fue enviada correctamente! El equipo de Sistemas se pondrá en contacto.', 'success')
        return redirect(url_for('exito'))

    total = get_db().execute('SELECT COUNT(*) FROM ticket').fetchone()[0]
    return render_template('index.html', sectores=SECTORES, form_data={}, total_tickets=total)


@app.route('/exito')
def exito():
    return render_template('exito.html')


@app.route('/solicitudes')
def solicitudes():
    db = get_db()
    filtro_estado = request.args.get('estado', '')
    busqueda = request.args.get('q', '').strip()[:200]

    query = 'SELECT * FROM ticket WHERE 1=1'
    params = []
    if filtro_estado and filtro_estado in ESTADOS:
        query += ' AND estado = ?'
        params.append(filtro_estado)
    if busqueda:
        query += ' AND (nombre LIKE ? OR descripcion LIKE ? OR sector LIKE ?)'
        params.extend([f'%{busqueda}%', f'%{busqueda}%', f'%{busqueda}%'])
    query += ' ORDER BY fecha_creacion DESC'
    tickets = db.execute(query, params).fetchall()

    conteo = {e: 0 for e in ESTADOS}
    for fila in db.execute('SELECT estado, COUNT(*) as n FROM ticket GROUP BY estado').fetchall():
        conteo[fila['estado']] = fila['n']

    return render_template('solicitudes.html',
                           tickets=tickets, estados=ESTADOS, conteo=conteo,
                           filtro_estado=filtro_estado, busqueda=busqueda)


@app.route('/solicitudes/<int:ticket_id>')
def ver_solicitud(ticket_id):
    db = get_db()
    ticket = db.execute('SELECT * FROM ticket WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        flash('Solicitud no encontrada.', 'danger')
        return redirect(url_for('solicitudes'))
    return render_template('solicitud_detalle.html', ticket=ticket)


# ── Rutas de autenticación ───────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if session.get('admin_logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr or '0.0.0.0'

        if _ip_bloqueada(ip):
            flash('Demasiados intentos fallidos. Esperá 5 minutos antes de volver a intentar.', 'danger')
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        admin = db.execute('SELECT * FROM admin WHERE username = ?', (username,)).fetchone()
        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = admin['username']
            flash(f'Bienvenido, {admin["username"]}.', 'success')
            return redirect(url_for('dashboard'))

        _registrar_intento_fallido(ip)
        restantes = _MAX_INTENTOS - len(_login_attempts[ip])
        if restantes > 0:
            flash(f'Usuario o contraseña incorrectos. Intentos restantes: {restantes}.', 'danger')
        else:
            flash('Cuenta bloqueada temporalmente por 5 minutos.', 'danger')

    return render_template('login.html')


@app.route('/admin/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))


# ── Rutas de administración ──────────────────────────────────────────────────

@app.route('/admin')
@login_required
def dashboard():
    db = get_db()
    filtro_estado = request.args.get('estado', '')
    filtro_sector = request.args.get('sector', '')
    busqueda = request.args.get('q', '').strip()[:200]

    query = 'SELECT * FROM ticket WHERE 1=1'
    params = []

    if filtro_estado and filtro_estado in ESTADOS:
        query += ' AND estado = ?'
        params.append(filtro_estado)
    if filtro_sector and filtro_sector in SECTORES:
        query += ' AND sector = ?'
        params.append(filtro_sector)
    if busqueda:
        query += ' AND (nombre LIKE ? OR descripcion LIKE ?)'
        params.extend([f'%{busqueda}%', f'%{busqueda}%'])

    query += ' ORDER BY fecha_creacion DESC'
    tickets = db.execute(query, params).fetchall()

    conteo = {estado: 0 for estado in ESTADOS}
    totales = db.execute('SELECT estado, COUNT(*) as n FROM ticket GROUP BY estado').fetchall()
    for fila in totales:
        conteo[fila['estado']] = fila['n']

    return render_template('admin/dashboard.html',
                           tickets=tickets,
                           estados=ESTADOS,
                           sectores=SECTORES,
                           conteo=conteo,
                           filtro_estado=filtro_estado,
                           filtro_sector=filtro_sector,
                           busqueda=busqueda)


@app.route('/admin/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ver_ticket(ticket_id):
    db = get_db()
    ticket = db.execute('SELECT * FROM ticket WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        flash('Ticket no encontrado.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        nuevo_estado = request.form.get('estado', '').strip()
        notas = request.form.get('notas_admin', '').strip()

        if nuevo_estado not in ESTADOS:
            flash('Estado inválido.', 'danger')
            return redirect(url_for('ver_ticket', ticket_id=ticket_id))

        if len(notas) > 5000:
            flash('Las notas no pueden superar los 5000 caracteres.', 'danger')
            return redirect(url_for('ver_ticket', ticket_id=ticket_id))

        ahora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            'UPDATE ticket SET estado = ?, notas_admin = ?, fecha_actualizacion = ? WHERE id = ?',
            (nuevo_estado, notas, ahora, ticket_id)
        )
        db.commit()
        flash('Ticket actualizado correctamente.', 'success')
        return redirect(url_for('ver_ticket', ticket_id=ticket_id))

    return render_template('admin/ticket.html', ticket=ticket, estados=ESTADOS)


@app.route('/admin/ticket/<int:ticket_id>/eliminar', methods=['POST'])
@login_required
def eliminar_ticket(ticket_id):
    db = get_db()
    ticket = db.execute('SELECT imagen FROM ticket WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        flash('Ticket no encontrado.', 'danger')
        return redirect(url_for('dashboard'))
    if ticket['imagen']:
        ruta = os.path.join(app.config['UPLOAD_FOLDER'], ticket['imagen'])
        try:
            if os.path.exists(ruta):
                os.remove(ruta)
        except OSError:
            pass  # imagen ya borrada o sin permisos; continúa igual
    db.execute('DELETE FROM ticket WHERE id = ?', (ticket_id,))
    db.commit()
    flash('Ticket eliminado.', 'info')
    return redirect(url_for('dashboard'))


# ── Filtro de templates ──────────────────────────────────────────────────────

@app.template_filter('estado_label')
def estado_label(estado):
    return ESTADOS.get(estado, estado)


@app.errorhandler(413)
def archivo_muy_grande(e):
    flash('La imagen es demasiado grande. El límite es 5 MB.', 'danger')
    return redirect(url_for('index'))


@app.template_filter('estado_badge')
def estado_badge(estado):
    colores = {
        'en_espera': 'warning',
        'en_proceso': 'dark',
        'terminado':  'success',
        'anulado':    'secondary',
    }
    return colores.get(estado, 'light')


@app.template_filter('badge_text')
def badge_text(estado):
    # warning usa texto oscuro; el resto fondo oscuro/color → texto blanco
    return 'text-dark' if estado == 'en_espera' else 'text-white'


if __name__ == '__main__':
    init_db()
    # Debug desactivado por defecto. Para activar: set FLASK_DEBUG=1
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=5000)
