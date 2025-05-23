from flask import Flask, render_template, request, redirect, url_for, session, send_file
import pyodbc
from datetime import datetime
from functools import wraps 
import bcrypt
import pandas as pd
import io

app = Flask(__name__)
app.secret_key = 'clave_secreta_de_que_payaso'  

conn_string = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=DESKTOP-03BPJRV; DATABASE=Entradas;Trusted_Connection=yes; Encrypt=no;'

def get_db_connection():
    try:
        conn = pyodbc.connect(conn_string)
        return conn
    except pyodbc.Error as e:
        raise Exception(f"Database connection error: {e}")


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session or session.get('rol') != 'Administrador':
            session['mensaje'] = {
                'tipo': 'error', 
                'text': 'Acceso restringido: se requieren privilegios de Administrador'
            }
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


BCRYPT_LOG_ROUNDS = 12

def hash_password(password):
    # Convierte la contraseña a bytes
    password_bytes = password.encode('utf-8')
    # Genera el salt y hashea la contraseña
    salt = bcrypt.gensalt(BCRYPT_LOG_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def check_password(hashed_password, user_password):
    # Convierte ambas contraseñas a bytes
    hashed_bytes = hashed_password.encode('utf-8')
    user_bytes = user_password.encode('utf-8')
    # Verifica si coinciden
    return bcrypt.checkpw(user_bytes, hashed_bytes)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        matricula = request.form.get('txtmatricula').strip()
        btn_entrada = request.form.get('btnentrada')
        btn_salida = request.form.get('btnsalida')

        conn = get_db_connection()
        cursor = conn.cursor()
        mensaje = None

        cursor.execute("SELECT Nombre FROM Alumnos WHERE Matricula = ?", (matricula,))
        alumno = cursor.fetchone()

        if not alumno:
            mensaje = {'tipo': 'error', 'text': 'La matrícula ingresada no se encuentra registrada en el sistema. Si está seguro de que es correcta, por favor, informe al responsable de la biblioteca para que pueda añadirla.'}
        else:
            if btn_entrada == 'ok':
                cursor.execute("SELECT * FROM Registros WHERE Matricula = ? AND Salida IS NULL", (matricula,))
                registro = cursor.fetchone()
                if registro:
                    mensaje = {'tipo': 'error', 'text': 'Ya tienes una entrada registrada.'}
                else:
                    entrada = datetime.now()
                    cursor.execute("INSERT INTO Registros (Matricula, Entrada) VALUES (?, ?)", (matricula, entrada))
                    conn.commit()
                    mensaje = {
                        'tipo': 'success',
                        'text': f'Entrada registrada correctamente para <br><strong>{alumno.Nombre}</strong><br>Hora: <strong>{entrada.strftime("%H:%M:%S")}</strong>'
                    }

            elif btn_salida == 'ok':
                cursor.execute("SELECT * FROM Registros WHERE Matricula = ? AND Salida IS NULL", (matricula,))
                registro = cursor.fetchone()
                if registro:
                    salida = datetime.now()
                    cursor.execute("UPDATE Registros SET Salida = ? WHERE Matricula = ? AND Salida IS NULL", (salida, matricula))
                    conn.commit()
                    mensaje = {
                        'tipo': 'success',
                        'text': f'Salida registrada correctamente para <br><strong>{alumno.Nombre}</strong><br>Hora: <strong>{salida.strftime("%H:%M:%S")}</strong>'
                    }
                else:
                    mensaje = {'tipo': 'error', 'text': 'No tienes ninguna entrada pendiente para registrar salida.'}

        cursor.close()
        conn.close()
        
        session['mensaje'] = mensaje
        return redirect(url_for('index'))

    mensaje = session.pop('mensaje', None)
    return render_template('index.html', mensaje=mensaje)

from flask import session

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT usuario, contraseña, rol FROM usuarios 
                WHERE usuario = ?
            """, (usuario,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and check_password(user.contraseña, password):
                session['usuario'] = user.usuario
                session['rol'] = user.rol
                return redirect(url_for('dashboard'))
            else:
                session['mensaje'] = {'tipo': 'error', 'text': 'Usuario o contraseña incorrectos'}
                return redirect(url_for('login'))
        except Exception as e:
            session['mensaje'] = {'tipo': 'error', 'text': f'Error al conectar a la base de datos: {e}'}
            return redirect(url_for('login'))

    mensaje = session.pop('mensaje', None)
    return render_template('login.html', mensaje=mensaje)



@app.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    # Configuración de paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Registros por página

    # Parámetros de búsqueda
    alumnos_seleccionados = request.args.getlist('alumnos')
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Consulta para obtener la lista de alumnos
    cursor.execute("SELECT Matricula, Nombre FROM Alumnos")
    alumnos = cursor.fetchall()

    # Consulta base para obtener los registros de asistencia
    query = """
        SELECT
            a.Matricula,
            a.Nombre,
            r.ID,
            r.Entrada,
            r.Salida
        FROM Alumnos a
        INNER JOIN Registros r ON a.Matricula = r.Matricula
    """

    conditions = []
    params = []

    # Aplicar filtros si existen
    if alumnos_seleccionados:
        placeholders = ', '.join(['?'] * len(alumnos_seleccionados))
        conditions.append(f"a.Matricula IN ({placeholders})")
        params.extend(alumnos_seleccionados)

    # Filtro por rango de fechas
    if fecha_inicio and fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) BETWEEN ? AND ?")
        params.extend([fecha_inicio, fecha_fin])
    elif fecha_inicio:
        conditions.append("CAST(r.Entrada AS DATE) >= ?")
        params.append(fecha_inicio)
    elif fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) <= ?")
        params.append(fecha_fin)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # Ordenar por fecha más reciente primero
    query += " ORDER BY r.Entrada DESC"

    # Paginación para SQL Server
    query += " OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
    params.extend([(page - 1) * per_page, per_page])

    cursor.execute(query, params)
    registros = cursor.fetchall()

    # Consulta para contar el total de registros
    count_query = """
        SELECT COUNT(*)
        FROM Alumnos a
        INNER JOIN Registros r ON a.Matricula = r.Matricula
    """
    if conditions:
        count_query += " WHERE " + " AND ".join(conditions)

    cursor.execute(count_query, params[:-2])  # Excluimos los parámetros de paginación
    total_registros = cursor.fetchone()[0]
    total_paginas = (total_registros + per_page - 1) // per_page

    cursor.close()
    conn.close()

    mensaje = session.pop('mensaje', None)

    return render_template('dashboard.html',
                         registros=registros,
                         alumnos=alumnos,  # Pasar la lista de alumnos al template
                         mensaje=mensaje,
                         page=page,
                         per_page=per_page,
                         total_paginas=total_paginas,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin,
                         alumnos_seleccionados=alumnos_seleccionados  
                         )



@app.route('/eliminar/<int:id>')
@admin_required
def eliminar_asistencia(id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Registros WHERE ID = ?", (id,))
    conn.commit()
    cursor.close()
    conn.close()

    # Guardar mensaje en session para mostrar SweetAlert en el dashboard
    session['mensaje'] = {'tipo': 'success', 'text': 'Registro eliminado correctamente.'}

    return redirect(url_for('dashboard'))



@app.route('/modificar', methods=['POST'])
@admin_required
def modificar_asistencia():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    id_registro = request.form.get('id')
    entrada_str = request.form.get('entrada')
    salida_str = request.form.get('salida')

    try:
        entrada = datetime.strptime(entrada_str, '%Y-%m-%dT%H:%M') if entrada_str else None
        salida = datetime.strptime(salida_str, '%Y-%m-%dT%H:%M') if salida_str else None
    except ValueError:
        session['mensaje'] = {'tipo': 'error', 'text': 'Formato de fecha/hora incorrecto.'}
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE Registros SET Entrada = ?, Salida = ? WHERE ID = ?",
            (entrada, salida, id_registro)
        )
        conn.commit()
        session['mensaje'] = {'tipo': 'success', 'text': 'Registro modificado correctamente.'}
    except Exception as e:
        session['mensaje'] = {'tipo': 'error', 'text': f'Error al modificar el registro: {e}'}
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()  # Esto elimina todo, incluido el rol
    return redirect(url_for('login'))

@app.route('/alumnos', methods=['GET', 'POST'])
@admin_required
def alumnos():
    
    if 'usuario' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        matricula = request.form.get('matricula', '').strip()
        nombre = request.form.get('nombre', '').strip()

        if not matricula or not nombre:
            session['mensaje'] = {'tipo': 'error', 'text': 'Todos los campos son obligatorios.'}
        else:
            try:
                cursor.execute("SELECT * FROM Alumnos WHERE Matricula = ?", (matricula,))
                existe = cursor.fetchone()
                if existe:
                    session['mensaje'] = {'tipo': 'error', 'text': 'La matrícula ya está registrada.'}
                else:
                    cursor.execute("INSERT INTO Alumnos (Matricula, Nombre) VALUES (?, ?)", (matricula, nombre))
                    conn.commit()
                    session['mensaje'] = {'tipo': 'success', 'text': 'Alumno agregado correctamente.'}
            except Exception as e:
                session['mensaje'] = {'tipo': 'error', 'text': f'Error al agregar alumno: {e}'}

        cursor.close()
        conn.close()
        return redirect(url_for('alumnos'))

    # GET con paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    # Obtener alumnos paginados
    cursor.execute("""
        SELECT * FROM Alumnos
        ORDER BY Nombre
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """, (offset, per_page))
    lista_alumnos = cursor.fetchall()

    # Contar total
    cursor.execute("SELECT COUNT(*) FROM Alumnos")
    total_alumnos = cursor.fetchone()[0]
    total_paginas = (total_alumnos + per_page - 1) // per_page

    cursor.close()
    conn.close()

    mensaje = session.pop('mensaje', None)
    return render_template(
        'alumnos.html',
        alumnos=lista_alumnos,
        mensaje=mensaje,
        page=page,
        per_page=per_page,
        total_paginas=total_paginas
    )


@app.route('/eliminar_alumno/<matricula>')
@admin_required
def eliminar_alumno(matricula):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM Registros WHERE Matricula = ?", (matricula,))
        cursor.execute("DELETE FROM Alumnos WHERE Matricula = ?", (matricula,))
        conn.commit()
        session['mensaje'] = {'tipo': 'success', 'text': 'Alumno y registros eliminados correctamente.'}
    except Exception as e:
        session['mensaje'] = {'tipo': 'error', 'text': f'Error al eliminar alumno y registros: {e}'}
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('alumnos'))


@app.route('/modificar_alumno', methods=['POST'])
@admin_required
def modificar_alumno():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    matricula_original = request.form.get('matricula_original').strip()
    matricula_nueva = request.form.get('matricula').strip()
    nombre = request.form.get('nombre').strip()

    if not matricula_nueva or not nombre:
        session['mensaje'] = {'tipo': 'error', 'text': 'Todos los campos son obligatorios.'}
        return redirect(url_for('alumnos'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Si la matrícula cambió, verificar que no exista otra igual
        if matricula_original != matricula_nueva:
            cursor.execute("SELECT * FROM Alumnos WHERE Matricula = ?", (matricula_nueva,))
            existe = cursor.fetchone()
            if existe:
                session['mensaje'] = {'tipo': 'error', 'text': 'La nueva matrícula ya está registrada.'}
                return redirect(url_for('alumnos'))

        # Actualizar datos en tabla Alumnos
        cursor.execute("""
            UPDATE Alumnos SET Matricula = ?, Nombre = ?
            WHERE Matricula = ?
        """, (matricula_nueva, nombre, matricula_original))

        # Si cambió la matrícula, actualizar también en Registros
        if matricula_original != matricula_nueva:
            cursor.execute("""
                UPDATE Registros SET Matricula = ?
                WHERE Matricula = ?
            """, (matricula_nueva, matricula_original))

        conn.commit()
        session['mensaje'] = {'tipo': 'success', 'text': 'Alumno modificado correctamente.'}
    except Exception as e:
        session['mensaje'] = {'tipo': 'error', 'text': f'Error al modificar alumno: {e}'}
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('alumnos'))

@app.route('/usuarios', methods=['GET', 'POST'])
@admin_required
def usuarios():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Check if this is an add user request
        if 'usuario' in request.form and 'password' in request.form:
            usuario = request.form.get('usuario', '').strip()
            password = request.form.get('password', '').strip()
            rol = request.form.get('rol', 'usuario')

            if not usuario or not password:
                session['mensaje'] = {'tipo': 'error', 'text': 'Todos los campos son obligatorios.'}
            else:
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    
                    # Verifica si el usuario ya existe
                    cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
                    if cursor.fetchone():
                        session['mensaje'] = {'tipo': 'error', 'text': 'El usuario ya existe.'}
                    else:
                        # Hashea la contraseña antes de almacenarla
                        hashed_password = hash_password(password)
                        cursor.execute(
                            "INSERT INTO usuarios (usuario, contraseña, rol) VALUES (?, ?, ?)",
                            (usuario, hashed_password, rol)
                        )
                        conn.commit()
                        session['mensaje'] = {'tipo': 'success', 'text': 'Usuario agregado correctamente.'}
                    
                    cursor.close()
                    conn.close()
                except Exception as e:
                    session['mensaje'] = {'tipo': 'error', 'text': f'Error al agregar usuario: {e}'}

            return redirect(url_for('usuarios'))

    # --- GET: Obtener lista de usuarios para mostrarla ---
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios")
        usuarios_lista = cursor.fetchall()
        cursor.close()
        conn.close()
    except Exception as e:
        usuarios_lista = []
        session['mensaje'] = {'tipo': 'error', 'text': f'Error al cargar usuarios: {e}'}
    
    mensaje = session.pop('mensaje', None)
    return render_template('usuarios.html', usuarios=usuarios_lista, mensaje=mensaje)



@app.route('/modificar_usuario', methods=['POST'])
@admin_required
def modificar_usuario():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario_original = request.form.get('usuario_original', '').strip()
    nuevo_usuario = request.form.get('usuario', '').strip()
    nueva_password = request.form.get('password', '').strip()

    if not nuevo_usuario:
        session['mensaje'] = {'tipo': 'error', 'text': 'El nombre de usuario no puede estar vacío.'}
        return redirect(url_for('usuarios'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM usuarios WHERE usuario = ? AND usuario != ?", (nuevo_usuario, usuario_original))
    if cursor.fetchone():
        session['mensaje'] = {'tipo': 'error', 'text': 'El nuevo nombre de usuario ya existe.'}
    else:
        if nueva_password:
            cursor.execute("UPDATE usuarios SET usuario = ?, contraseña = ? WHERE usuario = ?", 
                           (nuevo_usuario, nueva_password, usuario_original))
        else:
            cursor.execute("UPDATE usuarios SET usuario = ? WHERE usuario = ?", 
                           (nuevo_usuario, usuario_original))
        conn.commit()
        session['mensaje'] = {'tipo': 'success', 'text': 'Usuario modificado correctamente.'}

    cursor.close()
    conn.close()
    return redirect(url_for('usuarios'))


@app.route('/eliminar_usuario/<usuario>')
@admin_required
def eliminar_usuario(usuario):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario_actual = session['usuario']

    if usuario == usuario_actual:
        session['mensaje'] = {
            'tipo': 'error',
            'text': 'No puedes eliminar el usuario con el que has iniciado sesión.'
        }
        return redirect(url_for('usuarios'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))
    conn.commit()

    session['mensaje'] = {'tipo': 'success', 'text': 'Usuario eliminado correctamente.'}

    cursor.close()
    conn.close()

    return redirect(url_for('usuarios'))


@app.route('/cambiar_contraseña', methods=['POST'])
@admin_required
def cambiar_contraseña():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario = request.form.get('usuario', '').strip()
    nueva_password = request.form.get('password', '').strip()

    if not nueva_password:
        session['mensaje'] = {'tipo': 'error', 'text': 'La contraseña no puede estar vacía.'}
        return redirect(url_for('usuarios'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Hashea la nueva contraseña
        hashed_password = hash_password(nueva_password)
        
        cursor.execute(
            "UPDATE usuarios SET contraseña = ? WHERE usuario = ?",
            (hashed_password, usuario)
        )
        conn.commit()
        session['mensaje'] = {'tipo': 'success', 'text': f'Contraseña cambiada para {usuario}.'}
    except Exception as e:
        session['mensaje'] = {'tipo': 'error', 'text': f'Error al cambiar contraseña: {e}'}
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('usuarios'))


@app.route('/agregar_usuario', methods=['GET', 'POST'])
@admin_required
def agregar_usuario():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password', '').strip()
        rol = request.form.get('rol', 'Usuario')  # Default role is 'usuario'

        if not usuario or not password:
            session['mensaje'] = {'tipo': 'error', 'text': 'Todos los campos son obligatorios.'}
            return redirect(url_for('agregar_usuario'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
            if cursor.fetchone():
                session['mensaje'] = {'tipo': 'error', 'text': 'El usuario ya existe.'}
            else:
                # Hash the password before storing
                hashed_password = hash_password(password)
                cursor.execute(
                    "INSERT INTO usuarios (usuario, contraseña, rol) VALUES (?, ?, ?)",
                    (usuario, hashed_password, rol)
                )
                conn.commit()
                session['mensaje'] = {'tipo': 'success', 'text': 'Usuario agregado correctamente.'}
                return redirect(url_for('usuarios'))
            
        except Exception as e:
            session['mensaje'] = {'tipo': 'error', 'text': f'Error al agregar usuario: {e}'}
        finally:
            cursor.close()
            conn.close()

    # GET request - show add user form
    mensaje = session.pop('mensaje', None)
    return render_template('agregar_usuario.html', mensaje=mensaje)


@app.route('/generar_reporte')
def generar_reporte():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    alumnos_raw = request.args.get('alumnos', '')
    alumnos_seleccionados = alumnos_raw.split(',') if alumnos_raw else []
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            a.Matricula,
            a.Nombre,
            r.Entrada,
            r.Salida,
            CAST(r.Entrada AS DATE) as Fecha
        FROM Alumnos a
        INNER JOIN Registros r ON a.Matricula = r.Matricula
    """
    conditions = []
    params = []

    if alumnos_seleccionados:
        placeholders = ', '.join(['?'] * len(alumnos_seleccionados))
        conditions.append(f"a.Matricula IN ({placeholders})")
        params.extend(alumnos_seleccionados)

    if fecha_inicio and fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) BETWEEN ? AND ?")
        params.extend([fecha_inicio, fecha_fin])
    elif fecha_inicio:
        conditions.append("CAST(r.Entrada AS DATE) >= ?")
        params.append(fecha_inicio)
    elif fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) <= ?")
        params.append(fecha_fin)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query + " ORDER BY Fecha, a.Nombre", params)
    rows_por_fecha = cursor.fetchall()

    cursor.execute(query + " ORDER BY a.Nombre, Fecha", params)
    rows_por_alumno = cursor.fetchall()

    import pandas as pd
    from datetime import datetime
    from collections import defaultdict
    from itertools import groupby

    def calcular_horas(entrada, salida):
        if entrada and salida:
            horas = (salida - entrada).total_seconds() / 3600
            return round(horas, 2)
        return 0

    df_fecha = pd.DataFrame.from_records(rows_por_fecha, columns=[col[0] for col in cursor.description])
    df_fecha['Horas trabajadas'] = df_fecha.apply(lambda x: calcular_horas(x['Entrada'], x['Salida']), axis=1)
    df_fecha['Mes'] = df_fecha['Fecha'].apply(lambda x: x.strftime('%B %Y'))
    df_fecha['Entrada'] = df_fecha['Entrada'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if x else '--')
    df_fecha['Salida'] = df_fecha['Salida'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if x else '--')
    df_fecha = df_fecha[['Mes', 'Fecha', 'Matricula', 'Nombre', 'Entrada', 'Salida', 'Horas trabajadas']]

    df_alumno = pd.DataFrame.from_records(rows_por_alumno, columns=[col[0] for col in cursor.description])
    df_alumno['Horas trabajadas'] = df_alumno.apply(lambda x: calcular_horas(x['Entrada'], x['Salida']), axis=1)
    df_alumno['Mes'] = df_alumno['Fecha'].apply(lambda x: x.strftime('%B %Y'))
    df_alumno['Entrada'] = df_alumno['Entrada'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if x else '--')
    df_alumno['Salida'] = df_alumno['Salida'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if x else '--')
    df_alumno = df_alumno[['Nombre', 'Matricula', 'Mes', 'Fecha', 'Entrada', 'Salida', 'Horas trabajadas']]

    output = pd.ExcelWriter('reporte_asistencias.xlsx', engine='xlsxwriter')
    workbook = output.book

    # Estilos
    header_format = workbook.add_format({
        'bold': True, 'font_color': 'white', 'bg_color': '#1F4E78',
        'align': 'center', 'valign': 'vcenter', 'border': 1
    })
    data_format = workbook.add_format({
        'border': 1, 'align': 'center', 'valign': 'vcenter'
    })
    hours_format = workbook.add_format({
        'num_format': '0.00', 'border': 1, 'align': 'center', 'valign': 'vcenter'
    })
    fecha_sep_format = workbook.add_format({'bg_color': '#D9E1F2', 'bold': True, 'border': 1})
    mes_sep_format = workbook.add_format({'bg_color': '#B4C6E7', 'bold': True, 'border': 1})
    alumno_sep_format = workbook.add_format({'bg_color': '#E2EFDA', 'bold': True, 'border': 1})
    total_format = workbook.add_format({'bold': True, 'border': 1, 'bg_color': '#FFF2CC'})
# Define formatos para fecha
    fecha_format = workbook.add_format({'num_format': 'dd/mm/yyyy', 'border': 1, 'align': 'center', 'valign': 'vcenter'})

    # ----------------- Hoja 1 -----------------
    worksheet1 = workbook.add_worksheet('Asistencias')
    worksheet1.freeze_panes(1, 0)
    headers1 = ['Mes', 'Fecha', 'Matricula', 'Nombre', 'Entrada', 'Salida', 'Horas trabajadas']
    for col, val in enumerate(headers1):
        worksheet1.write(0, col, val, header_format)

    grouped = df_fecha.groupby('Fecha')
    row_idx = 1
    for fecha, registros in grouped:
        fecha_str = fecha.strftime('%d de %B de %Y')
        worksheet1.merge_range(row_idx, 0, row_idx, 6, f"Asistencias del {fecha_str}", fecha_sep_format)
        row_idx += 1
        for _, reg in registros.iterrows():
            worksheet1.write(row_idx, 0, reg['Mes'], data_format)
            worksheet1.write_datetime(row_idx, 1, reg['Fecha'], fecha_format)  # Aquí escribo fecha con formato
            worksheet1.write(row_idx, 2, reg['Matricula'], data_format)
            worksheet1.write(row_idx, 3, reg['Nombre'], data_format)
            worksheet1.write(row_idx, 4, reg['Entrada'], data_format)
            worksheet1.write(row_idx, 5, reg['Salida'], data_format)
            worksheet1.write(row_idx, 6, reg['Horas trabajadas'], hours_format)
            row_idx += 1
        row_idx += 1
    
    anchos1 = calcular_ancho_columna(df_fecha, headers1)
    for i, ancho in enumerate(anchos1):
        worksheet1.set_column(i, i, ancho)


    alumnos_dict = defaultdict(list)
    for _, row in df_alumno.iterrows():
        alumnos_dict[f"{row['Nombre']} | {row['Matricula']}"].append(row)
   # ----------------- Hoja 2 -----------------
    worksheet2 = workbook.add_worksheet('Asistencia por alumnos')
    worksheet2.freeze_panes(1, 0)
    headers2 = ['Mes', 'Fecha', 'Matricula', 'Nombre', 'Entrada', 'Salida', 'Horas trabajadas']
    for col, val in enumerate(headers2):
        worksheet2.write(0, col, val, header_format)

    row_idx = 1
    for alumno_key, registros in alumnos_dict.items():
        nombre, matricula = alumno_key.split(" | ")
        fechas = [r['Fecha'] for r in registros]
        fecha_inicio_alumno = min(fechas).strftime('%d de %B de %Y')
        fecha_fin_alumno = max(fechas).strftime('%d de %B de %Y')
        encabezado = f"Reporte de {nombre} {matricula} del {fecha_inicio_alumno} al {fecha_fin_alumno}"
        worksheet2.merge_range(row_idx, 0, row_idx, 6, encabezado, alumno_sep_format)
        row_idx += 1

        # Ya no separamos por mes
        registros.sort(key=lambda x: x['Fecha'])  # Ordenar solo por fecha si se desea

        total_horas = 0

        for reg in registros:
            worksheet2.write(row_idx, 0, reg['Mes'], data_format)
            worksheet2.write_datetime(row_idx, 1, reg['Fecha'], fecha_format)
            worksheet2.write(row_idx, 2, reg['Matricula'], data_format)
            worksheet2.write(row_idx, 3, reg['Nombre'], data_format)
            worksheet2.write(row_idx, 4, reg['Entrada'], data_format)
            worksheet2.write(row_idx, 5, reg['Salida'], data_format)
            worksheet2.write(row_idx, 6, reg['Horas trabajadas'], hours_format)
            total_horas += reg['Horas trabajadas']
            row_idx += 1

        worksheet2.write(row_idx, 5, "Total horas:", total_format)
        worksheet2.write(row_idx, 6, total_horas, hours_format)
        row_idx += 2

    anchos2 = calcular_ancho_columna(df_alumno, headers2)
    for i, ancho in enumerate(anchos2):
        worksheet2.set_column(i, i, ancho)

    output.close()
    cursor.close()
    conn.close()

    return send_file('reporte_asistencias.xlsx', as_attachment=True)





def calcular_ancho_columna(df, columnas):
    # Devuelve una lista con el ancho máximo estimado por columna
    return [
        max([len(str(val)) for val in [col] + df[col].astype(str).tolist()]) + 2
        for col in columnas
    ]

@app.route('/generar_pdf')
def generar_pdf():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    from flask import request, send_file
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.platypus.flowables import AnchorFlowable
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import letter, landscape
    import io
    from collections import defaultdict

    # Obtener filtros igual que en dashboard
    alumnos_raw = request.args.get('alumnos', '')
    alumnos_seleccionados = alumnos_raw.split(',') if alumnos_raw else []
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    print("Alumnos seleccionados:", alumnos_seleccionados)
    print("Fecha inicio:", fecha_inicio)
    print("Fecha fin:", fecha_fin)
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            a.Matricula,
            a.Nombre,
            r.Entrada,
            r.Salida,
            CAST(r.Entrada AS DATE) as Fecha
        FROM Alumnos a
        INNER JOIN Registros r ON a.Matricula = r.Matricula
    """

    conditions = []
    params = []

    if alumnos_seleccionados:
        placeholders = ', '.join(['?'] * len(alumnos_seleccionados))
        conditions.append(f"a.Matricula IN ({placeholders})")
        params.extend(alumnos_seleccionados)

    if fecha_inicio and fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) BETWEEN ? AND ?")
        params.extend([fecha_inicio, fecha_fin])
    elif fecha_inicio:
        conditions.append("CAST(r.Entrada AS DATE) >= ?")
        params.append(fecha_inicio)
    elif fecha_fin:
        conditions.append("CAST(r.Entrada AS DATE) <= ?")
        params.append(fecha_fin)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY Fecha, a.Nombre"

    cursor.execute(query, params)
    rows = cursor.fetchall()

    def calcular_horas(entrada, salida):
        if entrada and salida:
            return round((salida - entrada).total_seconds() / 3600, 2)
        return 0

    registros_por_alumno = defaultdict(list)
    for matricula, nombre, entrada, salida, fecha in rows:
        registros_por_alumno[(matricula, nombre)].append((fecha, entrada, salida))

    # Crear PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Índice de Alumnos
    elements.append(Paragraph("Índice de Alumnos", styles['Title']))
    elements.append(Spacer(1, 12))
    for (matricula, nombre) in registros_por_alumno:
        anchor_name = f"{matricula}_anchor"
        link = f'<link href="#{anchor_name}">{nombre} - {matricula}</link>'
        elements.append(Paragraph(link, styles['Normal']))
        elements.append(Spacer(1, 6))
    elements.append(PageBreak())

    # Tabla orden cronológico
    elements.append(Paragraph("Reporte de Asistencias - Orden Cronológico", styles['Title']))
    elements.append(Spacer(1, 12))

    data_fecha = [["Fecha", "Matrícula", "Nombre", "Entrada", "Salida", "Horas trabajadas"]]
    table_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1F4E78')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]

    last_fecha = None
    row_index = 1
    for matricula, nombre, entrada, salida, fecha in rows:
        horas = calcular_horas(entrada, salida)
        if fecha != last_fecha:
            fecha_str = fecha.strftime('%d/%m/%Y') if fecha else '--'
            data_fecha.append([f"Fecha: {fecha_str}"] + [''] * 5)
            table_styles.append(('SPAN', (0, row_index), (-1, row_index)))
            table_styles.append(('BACKGROUND', (0, row_index), (-1, row_index), colors.HexColor('#DDEBF7')))
            table_styles.append(('TEXTCOLOR', (0, row_index), (-1, row_index), colors.black))
            table_styles.append(('FONTNAME', (0, row_index), (-1, row_index), 'Helvetica-Bold'))
            table_styles.append(('ALIGN', (0, row_index), (-1, row_index), 'LEFT'))
            last_fecha = fecha
            row_index += 1

        data_fecha.append([
            fecha.strftime('%d/%m/%Y') if fecha else '--',
            matricula,
            nombre,
            entrada.strftime('%H:%M:%S') if entrada else '--',
            salida.strftime('%H:%M:%S') if salida else '--',
            f"{horas:.2f}"
        ])
        row_index += 1

    table_fecha = Table(data_fecha, colWidths=[70, 50, 225, 70, 70, 80])
    table_fecha.setStyle(TableStyle(table_styles))
    elements.append(table_fecha)
    elements.append(Spacer(1, 24))

    # Tabla por alumno con totales
    for (matricula, nombre), registros in registros_por_alumno.items():
        anchor_name = f"{matricula}_anchor"
        elements.append(AnchorFlowable(anchor_name))
        elements.append(Paragraph(f"{nombre} - {matricula}", styles['Heading3']))
        elements.append(Spacer(1, 6))

        data_alumno = [["Fecha", "Entrada", "Salida", "Horas trabajadas"]]
        total_horas = 0
        for fecha, entrada, salida in registros:
            horas = calcular_horas(entrada, salida)
            total_horas += horas
            data_alumno.append([
                fecha.strftime('%d/%m/%Y') if fecha else '--',
                entrada.strftime('%H:%M:%S') if entrada else '--',
                salida.strftime('%H:%M:%S') if salida else '--',
                f"{horas:.2f}"
            ])
        data_alumno.append(['', '', 'Total horas:', f"{total_horas:.2f}"])

        table_alumno = Table(data_alumno, colWidths=[100, 100, 100, 100])
        table_alumno.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4BACC6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#D9E1F2')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ]))
        elements.append(table_alumno)
        elements.append(Spacer(1, 24))

    doc.build(elements)
    buffer.seek(0)
    cursor.close()
    conn.close()
   

    return send_file(buffer, as_attachment=True, download_name="reporte_asistencias.pdf", mimetype='application/pdf')



# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    app.run(debug=True)