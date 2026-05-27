"""Sistema de Gestión de PQRS para Empresas Públicas - Sprint 1: Registro de Ciudadanos"""
import asyncio
import re
from datetime import datetime, date, timedelta
import random
import bcrypt
import base64
import json
import uuid
import os
from pathlib import Path
from urllib.parse import quote
import reflex as rx
from .usuario_model import Usuario, Solicitud
from sqlmodel import select, SQLModel, create_engine, text, Session
from rxconfig import config
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from starlette.staticfiles import StaticFiles
from dotenv import load_dotenv
from reflex.components import recharts as rc

# Carpeta donde se guardarán los archivos subidos por los usuarios
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "assets" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
from typing import Any

# Almacenamiento temporal para descargas (limpieza automática después de acceso)
TEMP_DOWNLOADS = {}

# Cargar variables de entorno
load_dotenv(dotenv_path=BASE_DIR / ".env", override=True)
print(f"[EMAIL] SENDER configurado: {bool(os.getenv('EMAIL_SENDER'))}")
print(f"[EMAIL] PASSWORD configurado: {bool(os.getenv('EMAIL_PASSWORD'))}")
print(f"[EMAIL] SMTP_SERVER: {os.getenv('SMTP_SERVER', 'smtp.gmail.com')}")
print(f"[EMAIL] SMTP_PORT: {os.getenv('SMTP_PORT', '587')}")
DEFAULT_DATABASE_PATH = BASE_DIR / "reflex.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
engine = create_engine(DATABASE_URL, echo=False)
SQLModel.metadata.create_all(engine)

# Asegura que las columnas necesarias existan en la tabla usuario
with engine.connect() as conn:
    result = conn.execute(text("PRAGMA table_info('usuario')"))
    columnas = [row[1] for row in result]
    if 'etnia' not in columnas:
        conn.execute(text("ALTER TABLE usuario ADD COLUMN etnia TEXT"))
    if 'persona_vulnerable' not in columnas:
        conn.execute(text("ALTER TABLE usuario ADD COLUMN persona_vulnerable TEXT"))
    conn.commit()

# Asegura que la columna persona_vulnerable exista en la tabla solicitud cuando se añada al modelo
with engine.connect() as conn:
    result = conn.execute(text("PRAGMA table_info('solicitud')"))
    columnas = [row[1] for row in result]
    if 'persona_vulnerable' not in columnas:
        conn.execute(text("ALTER TABLE solicitud ADD COLUMN persona_vulnerable TEXT"))
    conn.commit()

def tiene_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def confirmar_contraseña(contraseña: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(contraseña.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def validar_correo(correo: str) -> bool:
    # Solo rechaza si:
    # 1. No tiene @
    # 2. No tiene .
    # 3. La extensión es menor a 2 caracteres (ej: "com", "es", "co" son válidos, pero "c" no)
    if "@" not in correo:
        return False
    if "." not in correo:
        return False
    
    # Validar que después del punto hay al menos 2 caracteres
    partes = correo.split(".")
    if partes[-1].strip() and len(partes[-1].strip()) >= 2:
        return True
    return False

def cantida_minima_contraseña(contraseña: str) -> bool:
    # Requiere: al menos 8 caracteres, una mayúscula, una minúscula,
    # un número y al menos un carácter especial (cualquier signo de puntuación).
    return (
        len(contraseña) >= 8
        and re.search(r'[A-Z]', contraseña)
        and re.search(r'[a-z]', contraseña)
        and re.search(r'[0-9]', contraseña)
        and re.search(r'[^\w\s]', contraseña) is not None
    )

def sanitizar_nombre_archivo(nombre: str) -> str:
    """Sanitiza un nombre de archivo para evitar problemas de seguridad."""
    # Remover caracteres peligrosos
    nombre = re.sub(r'[^\w\s\-\.]', '', nombre)
    # Limitar la longitud
    nombre = nombre[:255]
    return nombre or "archivo"


def enviar_correo_bienvenida(email_destinatario: str, email_usuario: str):
    """Envía un correo de bienvenida con las credenciales de acceso.
    
    Este función es no-bloqueante: si el correo falla, registra el error pero no interrumpe el flujo.
    Asume que la contraseña en .env es una App Password de Gmail (16 caracteres).
    """
    try:
        # Obtener credenciales del archivo .env dentro de la función
        email_sender = os.getenv("EMAIL_SENDER")
        email_password = os.getenv("EMAIL_PASSWORD")
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        empresa_nombre = os.getenv("EMPRESA_NOMBRE", "Sistema de Gestión de PQRS")
        
        # Validar que existan credenciales
        if not email_sender:
            print(f"❌ [EMAIL] EMAIL_SENDER no configurado en .env. No se puede enviar correo a {email_destinatario}")
            return False
        
        if not email_password:
            print(f"❌ [EMAIL] EMAIL_PASSWORD no configurado en .env. No se puede enviar correo a {email_destinatario}")
            return False
        
        print(f"[EMAIL] Intentando enviar correo de bienvenida a: {email_destinatario}")
        
        # Crear mensaje
        mensaje = MIMEMultipart("alternative")
        mensaje["Subject"] = f"¡Bienvenido a {empresa_nombre}!"
        mensaje["From"] = email_sender
        mensaje["To"] = email_destinatario
        
        # Contenido del correo en HTML
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h1 style="color: #1e40af; text-align: center;">¡Bienvenido!</h1>
                    <p style="color: #333; font-size: 16px;">Hola,</p>
                    <p style="color: #333; font-size: 16px;">Tu registro en <strong>{empresa_nombre}</strong> ha sido exitoso. A continuación, encontrarás tus datos de acceso:</p>
                    
                    <div style="background-color: #f0f7ff; padding: 15px; border-left: 4px solid #1e40af; margin: 20px 0; border-radius: 5px;">
                        <p style="margin: 5px 0;"><strong>📧 Correo:</strong> <code>{email_usuario}</code></p>
                    </div>
                    
                    <p style="color: #333; font-size: 16px;">Para iniciar sesión, ingresa a:</p>
                    <p style="text-align: center; margin: 20px 0;">
                        <a href="http://localhost:3000/login" style="background-color: #1e40af; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Ir a Iniciar Sesión</a>
                    </p>
                    
                    <hr style="border: 1px solid #ddd; margin: 20px 0;">
                    <p style="color: #666; font-size: 14px;"><strong>Recuerda:</strong> Nunca compartas tu contraseña con terceros. El equipo de soporte nunca te pedirá tu contraseña.</p>
                    <p style="color: #666; font-size: 14px;">Si tienes preguntas o problemas, contacta a nuestro equipo de soporte.</p>
                    <p style="text-align: center; color: #999; font-size: 12px; margin-top: 30px;">© 2026 {empresa_nombre}. Todos los derechos reservados.</p>
                </div>
            </body>
        </html>
        """
        
        # Adjuntar el contenido
        parte_html = MIMEText(html, "html")
        mensaje.attach(parte_html)
        
        # Enviar correo con timeout y protocolo EHLO correcto
        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as servidor:
            servidor.ehlo()  # Identificación inicial requerida por algunos servidores SMTP
            servidor.starttls()
            servidor.ehlo()  # Re-identificación después de STARTTLS
            servidor.login(email_sender, email_password)
            servidor.sendmail(email_sender, email_destinatario, mensaje.as_string())
        
        print(f"✅ [EMAIL] Correo de bienvenida enviado exitosamente a {email_destinatario}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ [EMAIL] Error de autenticación SMTP al enviar a {email_destinatario}")
        print(f"   Causa: Las credenciales de Gmail son incorrectas o el acceso está bloqueado.")
        print(f"   Solución: Usa una App Password de Gmail (16 caracteres), no tu contraseña normal.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except smtplib.SMTPConnectError as e:
        print(f"❌ [EMAIL] Error de conexión SMTP al servidor {smtp_server}:{smtp_port}")
        print(f"   Causa: No se pudo conectar al servidor SMTP.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except TimeoutError as e:
        print(f"❌ [EMAIL] Timeout al conectar con el servidor SMTP {smtp_server}:{smtp_port}")
        print(f"   Causa: La conexión tardó más de 15 segundos.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except Exception as e:
        print(f"❌ [EMAIL] Error inesperado al enviar correo a {email_destinatario}")
        print(f"   Tipo de error: {type(e).__name__}")
        print(f"   Detalles: {str(e)}")
        return False


def enviar_correo_notificacion(email_destinatario: str, asunto: str, cuerpo: str) -> bool:
    """Envía una notificación por correo electrónico al ciudadano sobre actualizaciones en su solicitud.
    
    Este función es no-bloqueante: si el correo falla, registra el error pero no interrumpe el flujo.
    Asume que la contraseña en .env es una App Password de Gmail (16 caracteres).
    """
    try:
        # Obtener credenciales del archivo .env dentro de la función
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        email_sender = os.getenv("EMAIL_SENDER")
        email_password = os.getenv("EMAIL_PASSWORD")
        empresa_nombre = os.getenv("EMPRESA_NOMBRE", "Sistema de Gestión de PQRS")

        # Validar que existan credenciales
        if not email_sender:
            print(f"❌ [EMAIL] EMAIL_SENDER no configurado en .env. No se puede enviar notificación a {email_destinatario}")
            return False
        
        if not email_password:
            print(f"❌ [EMAIL] EMAIL_PASSWORD no configurado en .env. No se puede enviar notificación a {email_destinatario}")
            return False

        print(f"[EMAIL] Intentando enviar notificación a: {email_destinatario}")

        # Crear el mensaje
        mensaje = MIMEMultipart("alternative")
        mensaje['From'] = email_sender
        mensaje['To'] = email_destinatario
        mensaje['Subject'] = asunto

        # Agregar el cuerpo del mensaje
        body = f"{cuerpo}\n\nAtentamente,\nEquipo {empresa_nombre}"
        mensaje.attach(MIMEText(body, 'plain'))

        # Enviar correo con timeout y protocolo EHLO correcto
        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as servidor:
            servidor.ehlo()  # Identificación inicial requerida por algunos servidores SMTP
            servidor.starttls()
            servidor.ehlo()  # Re-identificación después de STARTTLS
            servidor.login(email_sender, email_password)
            servidor.sendmail(email_sender, email_destinatario, mensaje.as_string())

        print(f"✅ [EMAIL] Notificación enviada exitosamente a {email_destinatario}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ [EMAIL] Error de autenticación SMTP al enviar notificación a {email_destinatario}")
        print(f"   Causa: Las credenciales de Gmail son incorrectas o el acceso está bloqueado.")
        print(f"   Solución: Usa una App Password de Gmail (16 caracteres), no tu contraseña normal.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except smtplib.SMTPConnectError as e:
        print(f"❌ [EMAIL] Error de conexión SMTP al servidor {smtp_server}:{smtp_port}")
        print(f"   Causa: No se pudo conectar al servidor SMTP.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except TimeoutError as e:
        print(f"❌ [EMAIL] Timeout al conectar con el servidor SMTP {smtp_server}:{smtp_port}")
        print(f"   Causa: La conexión tardó más de 15 segundos.")
        print(f"   Detalles técnicos: {str(e)}")
        return False
        
    except Exception as e:
        print(f"❌ [EMAIL] Error inesperado al enviar notificación a {email_destinatario}")
        print(f"   Tipo de error: {type(e).__name__}")
        print(f"   Detalles: {str(e)}")
        return False


# quitar prints de prueba

class State(rx.State):


    # Dentro de class State, agrega estas variables:
    toast_mensaje: str = ""
    toast_tipo: str = ""  # "success" o "error"
    toast_visible: bool = False

    "En esta clase se define el estado de la aplicación, es decir, las variables que se van a usar en la aplicación y sus valores iniciales."
    state_auto_setters = True
    contraseña: str = ""
    confirmar_contraseña: str = ""
    correo: str = ""
    confirmar_correo: str = ""
    # Campos adicionales para registro extendido
    tipo_identificacion: str = ""
    numero_identificacion: str = ""
    nombres: str = ""
    apellidos: str = ""
    sexo: str = ""
    direccion: str = ""
    telefono: str = ""
    departamento: str = ""
    ciudad: str = ""
    etnia: str = ""
    persona_vulnerable_registro: str = ""
    # Estados de validación UX
    correo_validado: bool = False
    confirmar_correo_match: bool = False
    numero_identificacion_valid: bool = False
    nombres_valid: bool = False
    apellidos_valid: bool = False
    telefono_valid: bool = False
    departamento_valid: bool = False
    ciudad_valid: bool = False
    
    # Diccionario de departamentos y ciudades para dropdowns dinámicos
    departamentos_ciudades =  {
    "Amazonas": ["Leticia", "Puerto Nariño", "La Chorrera", "Tarapacá", "Puerto Santander", "Mirití-Paraná", "Puerto Alegría", "Puerto Arica", "La Victoria"],
    "Antioquia": ["Medellín", "Envigado", "Sabaneta", "Copacabana", "Girardota", "Barbosa", "Itagüí", "Bello", "Caldas", "La Estrella", "Rionegro", "La Ceja", "Apartadó", "Turbo", "Caucasia", "Santa Rosa de Osos"],
    "Arauca": ["Arauca", "Arauquita", "Cravo Norte", "Saravena", "Tame"],
    "Atlántico": ["Barranquilla", "Soledad", "Malambo", "Puerto Colombia", "Sabanalarga", "Baranoa", "Galapa"],
    "Bogotá D.C.": ["Bogotá D.C."],
    "Bolívar": ["Cartagena", "Turbaco", "Magangué", "Arjona", "El Carmen de Bolívar", "Mompox"],
    "Boyacá": ["Tunja", "Duitama", "Sogamoso", "Paipa", "Chiquinquirá", "Villa de Leyva", "Puerto Boyacá"],
    "Caldas": ["Manizales", "La Dorada", "Riosucio", "Chinchiná", "Villamaría", "Anserma"],
    "Caquetá": ["Florencia", "San Vicente del Caguán", "Puerto Rico", "Currillo"],
    "Casanare": ["Yopal", "Aguazul", "Paz de Ariporo", "Tauramena", "Maní"],
    "Cauca": ["Popayán", "Guachené", "Corinto", "Santander de Quilichao", "Puerto Tejada", "Patía"],
    "Cesar": ["Valledupar", "Aguachica", "Agustín Codazzi", "Bosconia", "Curumaní"],
    "Chocó": ["Quibdó", "Istmina", "Condoto", "Acandí", "Bahía Solano"],
    "Córdoba": ["Montería", "Cereté", "Sahagún", "Lorica", "Montelíbano", "Planeta Rica"],
    "Cundinamarca": ["Soacha", "Chía", "Sopó", "Tausa", "Tenjo", "Tena", "Tocaima", "Tocancipá", "Zipaquirá", "Fúquene", "Pacho", "Útica", "Villapinzón", "Villeta", "Facatativá", "Girardot", "Fusagasugá"],
    "Guainía": ["Inírida", "Barrancominas"],
    "Guaviare": ["San José del Guaviare", "Calamar", "El Retorno", "Miraflores"],
    "Huila": ["Neiva", "Pitalito", "Garzón", "La Plata", "Campoalegre", "San Agustín"],
    "La Guajira": ["Riohacha", "Maicao", "Uribia", "San Juan del Cesar", "Fonseca"],
    "Magdalena": ["Santa Marta", "Ciénaga", "Fundación", "El Banco", "Plato"],
    "Meta": ["Villavicencio", "Acacías", "Granada", "Puerto López", "Cumaral"],
    "Nariño": ["Pasto", "Ipiales", "Tumaco", "Sandoná", "Túquerres", "La Unión"],
    "Norte de Santander": ["Cúcuta", "Ocaña", "Pamplona", "Villa del Rosario", "Los Patios", "Tibú"],
    "Putumayo": ["Mocoa", "Puerto Asís", "Orito", "Valle del Guamuez", "Sibundoy"],
    "Quindío": ["Armenia", "Calarcá", "Filandia", "Circasia", "Montenegro", "Quimbaya"],
    "Risaralda": ["Pereira", "Dosquebradas", "Santa Rosa de Cabal", "La Virginia", "Belén de Umbría"],
    "San Andrés y Providencia": ["San Andrés", "Providencia"],
    "Santander": ["Bucaramanga", "Floridablanca", "Girón", "Piedecuesta", "Barrancabermeja", "San Gil", "Socorro"],
    "Sucre": ["Sincelejo", "Corozal", "Tolú", "San Marcos", "Sampués"],
    "Tolima": ["Ibagué", "Espinal", "Melgar", "Mariquita", "Honda", "Líbano"],
    "Valle del Cauca": ["Cali", "Palmira", "Yumbo", "Cartago", "Buenaventura", "Tuluá", "Buga", "Jamundí"],
    "Vaupés": ["Mitú", "Carurú", "Taraira"],
    "Vichada": ["Puerto Carreño", "La Primavera", "Santa Rosalía", "Cumaribo"]
}
    
    # Habeas data / autorizaciones
    acepta_notificaciones: bool = False
    acepta_politica_datos: bool = False
    # Para el formulario de solicitudes
    acepta_politica_solicitud: bool = False
    area_responsable: str = ""
    area_otro: str = ""
    tipo_solicitud: str = ""
    persona_vulnerable: str = ""
    asunto: str = ""
    descripcion: str = ""
    ubicacion: str = ""
    documento: str = ""
    documentos: list[Any] = []
    documento_nombres: list[str] = []
    documento_nombre: str = ""
    descripcion_len: int = 0
    query_solicitud: str = ""
    filter_tipo_solicitud: str = "Todas"
    filter_estado_solicitud: str = "Todas"
    solicitudes: list[dict[str, Any]] = []
    editar_solicitud_id: int = 0
    eliminar_solicitud_id: int = 0
    solicitud_mensaje: str = ""


    error_de_registro: str = ""
    succes: str = ""
    error_de_contraseña: str = ""
    succes2: str = ""
    
    id_usuario: int = 0
    es_autentica: bool = False
    email_actual: str = ""
    rol_usuario: str = ""
    correo_usuario: str = ""
    show_password: bool = False
    # Campos para cambiar contraseña
    current_password: str = ""
    new_password: str = ""
    confirm_new_password: str = ""
    change_pw_message: str = ""
    # Campos para cambiar rol de ciudadano a funcionario
    cambiar_rol_email: str = ""
    cambiar_rol_mensaje: str = ""
    usuarios_registrados: list[dict[str, Any]] = []
    # Campos para editar estado de solicitud
    editar_estado_id: int = 0
    nuevo_estado: str = ""
    respuesta_solicitud: str = ""
    mensaje_actualizar_estado: str = ""
    respuesta_documento: str = ""
    respuesta_documento_nombre: str = ""
    # Variables para modal de política y validaciones
    modal_politica_visible: bool = False
    archivo_error_mensaje: str = ""
    correo_confirmacion_visible: bool = False
    correo_confirmacion_mensaje: str = ""
    
    # Campos para asignación de área con mensaje
    asignar_area_id: int = 0
    asignar_area_mensaje: str = ""
    asignar_area_nombre: str = ""
    asignar_area_seleccionada: str = ""
    mensaje_asignacion: str = ""
    
    # Campos para consultar estado de solicitud
    consulta_radicado: str = ""
    solicitud_consultada: dict[str, Any] = {}
    consulta_mensaje: str = ""
    # Enlace generado tras exportar reportes (archivo descargable)
    export_href: str = ""
    export_filename: str = ""
    mostrar_menu_descarga: bool = False

    @rx.var
    def ciudades_disponibles(self) -> list[str]:
        """Retorna las ciudades del departamento seleccionado."""
        if self.departamento in self.departamentos_ciudades:
            return self.departamentos_ciudades[self.departamento]
        return []

    @rx.var
    def data_grafica_tipo(self) -> list[dict]:
        counts = self.estadisticas_por_tipo
        return [
            {"name": "Petición", "cantidad": counts.get("Petición", 0)},
            {"name": "Queja", "cantidad": counts.get("Queja", 0)},
            {"name": "Reclamo", "cantidad": counts.get("Reclamo", 0)},
            {"name": "Sugerencia", "cantidad": counts.get("Sugerencia", 0)},
        ]
    
    @rx.var
    def data_grafica_estado(self) -> list[dict]:
        return [
            {"name": "Radicada", "cantidad": int(self.numero_solicitudes_radicadas)},
            {"name": "Actualizada", "cantidad": int(self.numero_solicitudes_actualizadas)},
            {"name": "Cerrada", "cantidad": int(self.numero_solicitudes_cerradas)},
        ]

    def mostrar_toast(self, mensaje: str, tipo: str = "success"):
        self.toast_mensaje = mensaje
        self.toast_tipo = tipo
        self.toast_visible = True

    def export_reportes_csv(self):
        """Genera un CSV en memoria desde `self.solicitudes` para descarga."""
        try:
            import csv
            import io
            from datetime import datetime

            data = self.solicitudes or []
            if not data:
                self.mostrar_toast("No hay datos para exportar.", "warning")
                self.mostrar_menu_descarga = False
                return
            
            # Generar CSV en memoria
            output = io.StringIO()
            if data and isinstance(data[0], dict):
                writer = csv.DictWriter(output, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            else:
                output.write("Error: Datos en formato inválido")
            
            # Guardar en almacenamiento temporal
            csv_bytes = output.getvalue().encode('utf-8')
            filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv"
            download_id = str(uuid.uuid4())
            
            TEMP_DOWNLOADS[download_id] = {
                "data": csv_bytes,
                "filename": filename,
                "mime": "text/csv; charset=utf-8"
            }
            
            self.export_filename = filename
            self.mostrar_toast(f"✓ CSV generado. {len(data)} registros. Descargando...", "success")
            self.mostrar_menu_descarga = False
            self.export_href = f"/api/download/{download_id}"
            
        except Exception as e:
            print(f"ERROR en export_reportes_csv: {type(e).__name__}: {e}")
            self.mostrar_toast(f"Error: {str(e)[:100]}", "error")
            self.mostrar_menu_descarga = False

    def descargar_excel_y_abrir(self):
        """Genera Excel en memoria y dispara la descarga."""
        try:
            import io
            from datetime import datetime
            import pandas as pd

            data = self.solicitudes or []
            if not data:
                self.mostrar_toast("No hay datos para exportar.", "warning")
                return

            df = pd.DataFrame(data)
            output = io.BytesIO()
            df.to_excel(output, index=False, sheet_name="Solicitudes", engine="openpyxl")
            output.seek(0)

            filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.xlsx"
            return rx.download(
                data=output.read(),
                filename=filename,
                mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except ModuleNotFoundError:
            self.mostrar_toast("No está instalado pandas para exportar Excel.", "error")
        except Exception as e:
            print(f"ERROR en descargar_excel_y_abrir: {e}")
            self.mostrar_toast(f"Error exportando Excel: {str(e)[:100]}", "error")

    def descargar_csv_y_abrir(self):
        """Genera CSV en memoria y dispara la descarga."""
        try:
            import csv
            import io
            from datetime import datetime

            data = self.solicitudes or []
            if not data:
                self.mostrar_toast("No hay datos para exportar.", "warning")
                return

            output = io.StringIO()
            if data and isinstance(data[0], dict):
                writer = csv.DictWriter(output, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            else:
                output.write("Error: Datos en formato inválido")

            filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv"
            return rx.download(
                data=output.getvalue().encode('utf-8'),
                filename=filename,
                mime_type="text/csv; charset=utf-8"
            )
        except Exception as e:
            print(f"ERROR en descargar_csv_y_abrir: {e}")
            self.mostrar_toast(f"Error exportando CSV: {str(e)[:100]}", "error")


    def ocultar_toast(self):
        self.toast_visible = False
        self.toast_mensaje = ""

    def toggle_menu_descarga(self):
        """Alterna la visibilidad del menú de descarga."""
        self.mostrar_menu_descarga = not self.mostrar_menu_descarga
        
     
    @rx.var
    def numero_solicitudes(self) -> str:
        return str(len(self.solicitudes or []))
    
    @rx.var
    def numero_solicitudes_radicadas(self) -> str:
        return str(sum(1 for solicitud in (self.solicitudes or []) if solicitud.get('estado') == 'Radicada'))
    
    @rx.var
    def numero_solicitudes_actualizadas(self) -> str:
        return str(sum(1 for solicitud in (self.solicitudes or []) if solicitud.get('estado') == 'Actualizada'))
    
    @rx.var
    def numero_solicitudes_cerradas(self) -> str:
        return str(sum(1 for solicitud in (self.solicitudes or []) if solicitud.get('estado') == 'Cerrada'))
    
    @rx.var
    def estadisticas_por_tipo(self) -> dict[str, int]:
        counts = {"Petición": 0, "Queja": 0, "Reclamo": 0, "Sugerencia": 0}
        for solicitud in self.solicitudes or []:
            tipo = solicitud.get("tipo_solicitud")
            if tipo in counts:
                counts[tipo] += 1
        return counts

    @rx.var
    def max_registros_tipo(self) -> int:
        values = list(self.estadisticas_por_tipo.values())
        return max(values) if values else 1

    @rx.var(auto_deps=False)
    def monthly_response_times(self) -> list[dict]:
        """Calcula el tiempo promedio de respuesta por mes (Ene..Dic) a partir de self.solicitudes.
        Devuelve lista de dicts: {month: 'Ene', value: float}
        """
        # Nuevo comportamiento: generar serie diaria para los últimos 30 días
        today = date.today()
        start_date = today - timedelta(days=29)
        # preparar buckets por día
        buckets: dict[str, list[int]] = {}
        for i in range(30):
            d = start_date + timedelta(days=i)
            buckets[d.strftime("%Y-%m-%d")] = []

        for s in (self.solicitudes or []):
            try:
                frp = self._parse_dt(s.get('fecha_respuesta'))
                if not frp:
                    continue
                resp_date = frp.date()
                if resp_date < start_date or resp_date > today:
                    continue
                fr = self._parse_dt(s.get('fecha') or s.get('fecha_radicado'))
                if not fr:
                    continue
                start = fr.date() + timedelta(days=1)
                dias = self._business_days_between(start, resp_date, set())
                # If response happened same day and dias == 0, simulate 1-5 days for visualization/testing
                if dias == 0:
                    dias = random.randint(1, 5)
                    print(f"DEBUG - monthly_response_times: simulated dias={dias} for {s.get('radicado')}")
                key = resp_date.strftime("%Y-%m-%d")
                buckets.setdefault(key, []).append(dias)
            except Exception:
                continue

        result = []
        for i in range(30):
            d = start_date + timedelta(days=i)
            key = d.strftime("%Y-%m-%d")
            vals = buckets.get(key, [])
            avg = round(sum(vals) / len(vals), 1) if vals else 0
            label = d.strftime('%d %b')
            result.append({"month": label, "value": avg})
        print("DEBUG - monthly_response_times result:", result)

        # Si todos los valores son 0, usamos un fallback de simulación para visualización
        if all(item.get("value", 0) == 0 for item in result):
            simulated = []
            for i in range(30):
                d = start_date + timedelta(days=i)
                label = d.strftime('%d %b')
                # 60% probabilidad de mostrar un valor entre 0.5 y 4.0, else 0
                if random.random() < 0.6:
                    val = round(random.uniform(0.5, 4.0), 1)
                else:
                    val = 0
                simulated.append({"month": label, "value": val})
            print("DEBUG - monthly_response_times: using simulated fallback:", simulated)
            return simulated

        return result

    @rx.var
    def compliance_percentage(self) -> int:
        """Calcula un porcentaje simple de cumplimiento: solicitudes con 'cumple_plazo' truthy.
        """
        total = len(self.solicitudes or [])
        if total == 0:
            return 0
        cumple = sum(1 for s in (self.solicitudes or []) if s.get('cumple_plazo'))
        return int((cumple / total) * 100)

    @rx.var
    def compliance_chart_data(self) -> list[dict]:
        pct = int(self.compliance_percentage)
        return [
            {"name": "Cumplimiento", "value": pct},
            {"name": "Resto", "value": max(0, 100 - pct)},
        ]

    # --- Semáforo: días hábiles y conteos por color ---
    def _parse_dt(self, v):
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        try:
            # ISO format usually works
            return datetime.fromisoformat(v)
        except Exception:
            try:
                from dateutil import parser as _p
                return _p.parse(v)
            except Exception:
                return None

    def _is_business_day(self, d: date, holidays: set):
        return d.weekday() < 5 and d not in holidays

    def _business_days_between(self, start: date, end: date, holidays: set) -> int:
        if end < start:
            return 0
        days = 0
        cur = start
        while cur <= end:
            if self._is_business_day(cur, holidays):
                days += 1
            cur += timedelta(days=1)
        return days

    def _legal_days_for(self, tipo: str, detalle: str | None = None) -> int:
        if not tipo:
            return 15
        t = tipo.lower()
        d = (detalle or "").lower()
        if "consulta" in d or t == "consulta":
            return 30
        if "inform" in d or "copia" in d or "informacion" in d:
            return 10
        if t in ("peticion", "petición", "queja", "reclamo", "sugerencia"):
            return 15
        return 15


    @staticmethod
    def _compute_remaining_for_solicitud(solicitud: dict) -> dict:
        """Computa días restantes y color (fill) para una solicitud dada.
        Usa llaves comunes que retorna `_solicitud_a_dict` como `fecha` y `tipo_solicitud`.
        Retorna dict con `remaining` (int or None) y `fill` (hex color).
        """
        try:
            fecha_raw = solicitud.get("fecha") or solicitud.get("fecha_radicado")
            if not fecha_raw:
                return {"remaining": None, "fill": "gray"}
            # intentar parseo ISO, sino dateutil
            try:
                dt = datetime.fromisoformat(str(fecha_raw))
            except Exception:
                try:
                    from dateutil import parser as _p
                    dt = _p.parse(str(fecha_raw))
                except Exception:
                    return {"remaining": None, "fill": "gray"}

            start = dt.date() + timedelta(days=1)
            ref = date.today()
            if solicitud.get("fecha_respuesta"):
                try:
                    r = datetime.fromisoformat(str(solicitud.get("fecha_respuesta")))
                    ref = r.date()
                except Exception:
                    try:
                        from dateutil import parser as _p
                        r = _p.parse(str(solicitud.get("fecha_respuesta")))
                        ref = r.date()
                    except Exception:
                        pass

            # contar días hábiles (fines de semana excluidos). No usamos festivos aquí.
            days = 0
            cur = start
            while cur <= ref:
                if cur.weekday() < 5:
                    days += 1
                cur += timedelta(days=1)

            tipo = (solicitud.get("tipo_solicitud") or solicitud.get("tipo_pqrs") or "").lower()
            if "consulta" in tipo:
                legal = 30
            elif "inform" in tipo or "copia" in tipo or "informacion" in tipo:
                legal = 10
            elif tipo in ("peticion", "petición", "queja", "reclamo", "sugerencia"):
                legal = 15
            else:
                legal = 15

            remaining = legal - days
            if remaining <= 0:
                fill = "#ef4444"
            elif remaining <= 5:
                fill = "#f59e0b"
            else:
                fill = "#10b981"
            return {"remaining": remaining, "fill": fill}
        except Exception:
            return {"remaining": None, "fill": "gray"}

    @rx.var(auto_deps=False)
    def semaforo_counts(self) -> dict:
        # lee self.solicitudes y devuelve conteo por color
        holidays = set()  # puedes poblar con una consulta a festivos si la tienes
        counts = {"verde": 0, "amarillo": 0, "rojo": 0}
        # Estados que consideramos cerrados/resueltos (normalizados en minúsculas)
        closed_states = {"respondida", "respondido", "respondida", "respondida", "cerrada", "cerrado", "finalizada", "finalizado"}
        for s in (self.solicitudes or []):
            estado_raw = (s.get("estado") or "").strip().lower()
            # Si el estado está en la lista de cerrados, lo saltamos; así consideramos activo todo lo demás
            if estado_raw in closed_states:
                continue
            fr = self._parse_dt(s.get("fecha") or s.get("fecha_radicado"))
            if not fr:
                # intentar usar la llave 'fecha_radicado' si existe (compatibilidad)
                fr = self._parse_dt(s.get("fecha_radicado"))
            if not fr:
                continue
            start = fr.date() + timedelta(days=1)
            ref = date.today()
            if s.get("fecha_respuesta"):
                resp = self._parse_dt(s.get("fecha_respuesta"))
                if resp:
                    ref = resp.date()
            used = self._business_days_between(start, ref, holidays)
            # usar `tipo_solicitud` por consistencia con `_solicitud_a_dict`
            legal = self._legal_days_for(s.get("tipo_solicitud"), s.get("tipo_detalle") or s.get("asunto"))
            remaining = legal - used
            if remaining <= 0:
                counts["rojo"] += 1
            elif remaining <= 5:
                counts["amarillo"] += 1
            else:
                counts["verde"] += 1
        return counts

    @rx.var
    def semaforo_chart_data(self) -> list[dict]:
        c = self.semaforo_counts
        return [
            {"name": "Verde", "value": c.get("verde", 0), "fill": "#10b981"},
            {"name": "Amarillo", "value": c.get("amarillo", 0), "fill": "#f59e0b"},
            {"name": "Rojo", "value": c.get("rojo", 0), "fill": "#ef4444"},
        ]

    @rx.var
    def semaforo_total(self) -> int:
        c = self.semaforo_counts
        total_from_counts = int(c.get("verde", 0) + c.get("amarillo", 0) + c.get("rojo", 0))
        # Fallback: si no hay conteos, usar data_grafica_tipo (cantidad)
        fallback = 0
        try:
            for it in (self.data_grafica_tipo or []):
                fallback += int(it.get("cantidad", 0))
        except Exception:
            fallback = 0
        return max(total_from_counts, fallback)

    @rx.var
    def semaforo_bar_data(self) -> list[dict]:
        # Devuelve una lista con un único registro que contiene los valores por color
        c = self.semaforo_counts
        total = int(c.get("verde", 0) + c.get("amarillo", 0) + c.get("rojo", 0))
        if total > 0:
            return [{
                "name": "Semáforo",
                "verde": int(c.get("verde", 0)),
                "amarillo": int(c.get("amarillo", 0)),
                "rojo": int(c.get("rojo", 0)),
            }]
        # Fallback a partir de data_grafica_tipo: sumar todas las solicitudes en verde (representación)
        fallback = 0
        try:
            for it in (self.data_grafica_tipo or []):
                fallback += int(it.get("cantidad", 0))
        except Exception:
            fallback = 0
        return [{"name": "Semáforo", "verde": fallback, "amarillo": 0, "rojo": 0}]

    @rx.var
    def top_areas(self) -> list[dict]:
        """Devuelve las top 3 áreas por cantidad de solicitudes.
        """
        counts = {}
        for s in (self.solicitudes or []):
            a = s.get('area_responsable') or 'N/A'
            counts[a] = counts.get(a, 0) + 1
        items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:3]
        return [{"name": name, "total": total} for name, total in items]
    
    @rx.var
    def solicitudes_filtradas(self) -> list[dict]:
        query = (self.query_solicitud or "").strip().lower()
        tipo = (self.filter_tipo_solicitud or "Todas").lower()
        estado = (self.filter_estado_solicitud or "Todas").lower()
        resultados = []
        for solicitud in self.solicitudes or []:
            texto = " ".join(
                str(solicitud.get(field, "") or "")
                for field in ("radicado", "asunto", "descripcion", "creado_por")
            ).lower()
            if query and query not in texto:
                continue
            if tipo != "todas" and solicitud.get("tipo_solicitud", "").lower() != tipo:
                continue
            if estado != "todas" and solicitud.get("estado", "").lower() != estado:
                continue
            resultados.append(solicitud)
        return resultados

    @rx.var
    def documento_nombres_joined(self) -> str:
        return ", ".join(self.documento_nombres or [])
    
    @rx.var
    def documento_nombres_count(self) -> str:
        return str(len(self.documento_nombres or []))

    def _documento_size(self, item: Any) -> int:
        if not isinstance(item, dict):
            return 0
        nombre = item.get("name") or item.get("filename") or ""
        ext = os.path.splitext(nombre)[1].lower().lstrip(".")
        if ext not in {"pdf", "png", "jpg", "jpeg"}:
            return 0
        try:
            return int(item.get("size") or 0)
        except Exception:
            return 0

    @rx.var
    def documento_tamano_total_bytes(self) -> int:
        return sum(self._documento_size(item) for item in self.documentos or [])

    @rx.var
    def documento_tamano_total(self) -> str:
        total = self.documento_tamano_total_bytes
        return f"{total / (1024 * 1024):.2f} MB"
    
    @rx.var
    def documento_espacio_restante(self) -> str:
        """Calcula los MB libres sobre el límite de 10 MB totales."""
        MAX_TOTAL = 10 * 1024 * 1024  # 10 MB
        usado = self.documento_tamano_total_bytes
        restante = MAX_TOTAL - usado
        if restante <= 0:
            return "0.00 MB libres"
        return f"{restante / (1024 * 1024):.2f} MB libres"
    
    @rx.var
    def usuarios_registrados_count(self) -> int:
        return len(self.usuarios_registrados or [])
    
    @rx.var
    def solicitud_consultada_adjuntos(self) -> list[dict]:
        documento_str = self.solicitud_consultada.get("documento", "")
        documento_basename_str = self.solicitud_consultada.get("documento_basename", "")
        
        if not documento_str:
            return []
        
        try:
            documentos = json.loads(documento_str)
            basenames = json.loads(documento_basename_str) if documento_basename_str else []
            
            result = []
            for i, doc in enumerate(documentos or []):
                basename = basenames[i] if i < len(basenames) else f"Documento {i+1}"
                result.append({
                    "basename": basename,
                    "href": f"/assets/uploads/{doc.split('/')[-1]}"
                })
            return result
        except:
            return []
    
    
    
    def set_query_solicitud(self, value: str):
        self.query_solicitud = value or ""
    
    def set_filter_tipo_solicitud(self, value: str):
        self.filter_tipo_solicitud = value or "Todas"

    def set_filter_estado_solicitud(self, value: str):
        self.filter_estado_solicitud = value or "Todas"

    def buscar_solicitudes(self):
        self.query_solicitud = (self.query_solicitud or "").strip()

    def set_new_password(self, value: str):
        self.new_password = value
    
    def set_confirm_new_password(self, value: str):
        self.confirm_new_password = value
    
    def borrar_mensajes_de_estado(self):
        self.error_de_registro = ""
        self.succes = ""
        self.error_de_contraseña = ""
        self.succes2 = ""

    def limpiar_formulario_registro(self):
        """Limpia todos los campos del formulario de registro."""
        # Campos de acceso
        self.correo = ""
        self.confirmar_correo = ""
        self.contraseña = ""
        self.confirmar_contraseña = ""
        
        # Campos de identificación
        self.tipo_identificacion = ""
        self.numero_identificacion = ""
        self.nombres = ""
        self.apellidos = ""
        self.sexo = ""
        self.direccion = ""
        self.telefono = ""
        
        # Campos de ubicación
        self.departamento = ""
        self.ciudad = ""
        
        # Campos de diversidad
        self.etnia = ""
        self.persona_vulnerable_registro = ""
        
        # Autorizaciones
        self.acepta_notificaciones = False
        self.acepta_politica_datos = False
        
        # Estados de validación
        self.correo_validado = False
        self.confirmar_correo_match = False
        self.numero_identificacion_valid = False
        self.nombres_valid = False
        self.apellidos_valid = False
        self.telefono_valid = False
        self.departamento_valid = False
        self.ciudad_valid = False
        
        # Mensajes (NO limpiar self.succes aquí, se limpiará cuando el usuario interactúe)
        self.error_de_registro = ""
        self.correo_confirmacion_visible = False
        self.correo_confirmacion_mensaje = ""
        self.show_password = False

    def validacion_login(self) -> bool:
        """Valida solo correo y contraseña para el login (sin confirmar_correo)."""
        # Validar que el correo no esté vacío
        if not self.correo or not self.correo.strip():
            self.error_de_registro = "El correo electrónico es obligatorio."
            return False
        
        # Validar formato del correo
        if not validar_correo(self.correo):
            self.error_de_registro = "Correo no válido."
            return False
        
        # Validar que la contraseña no esté vacía
        if not self.contraseña or not self.contraseña.strip():
            self.error_de_registro = "La contraseña es obligatoria."
            return False
        
        return True

    def validacion_de_entradas(self, require_strong_pw: bool = True) -> bool:
        self.correo_confirmacion_visible = False
        self.correo_confirmacion_mensaje = ""
        
        # Validar que el correo no esté vacío
        if not self.correo or not self.correo.strip():
            self.error_de_registro = "El correo electrónico es obligatorio."
            return False
        
        # Validar formato del correo
        if not validar_correo(self.correo):
            self.error_de_registro = "Correo no válido."
            self.correo_confirmacion_visible = True
            self.correo_confirmacion_mensaje = "Correo no válido."
            return False
        
        # Validar que el correo confirmado no esté vacío
        if not self.confirmar_correo or not self.confirmar_correo.strip():
            self.error_de_registro = "Debes confirmar tu correo electrónico."
            return False
        
        # Validar que el correo confirmado coincida con el correo principal
        if self.correo != self.confirmar_correo:
            self.error_de_registro = "Los correos electrónicos no coinciden."
            return False
        
        self.correo_confirmacion_visible = True
        self.correo_confirmacion_mensaje = "Correo válido."
        
        # Validar que la contraseña no esté vacía
        if not self.contraseña or not self.contraseña.strip():
            self.error_de_registro = "La contraseña es obligatoria."
            return False
        
        # Validar que la confirmación de contraseña no esté vacía
        if not self.confirmar_contraseña or not self.confirmar_contraseña.strip():
            self.error_de_registro = "Debes confirmar tu contraseña."
            return False
        
        if require_strong_pw and not cantida_minima_contraseña(self.contraseña):
            self.error_de_registro = "La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales."
            return False
        if require_strong_pw and self.contraseña != self.confirmar_contraseña:
            self.error_de_registro = "Las contraseñas no coinciden."
            return False
        return True
    def validar_campo_simple(self, campo: str) -> bool:
        """Validaciones simples para mostrar iconos de confirmación.
        Retorna True si el campo parece correcto."""
        val = getattr(self, campo, "")
        ok = False
        if campo == "telefono":
            ok = isinstance(val, str) and len(val) >= 7
        elif campo == "numero_identificacion":
            ok = isinstance(val, str) and len(val) >= 6
        elif campo == "correo":
            ok = validar_correo(val)
        else:
            ok = bool(val and str(val).strip())
        # set dedicated flags for reactivity
        if campo == "telefono":
            self.telefono_valid = ok
        elif campo == "numero_identificacion":
            self.numero_identificacion_valid = ok
        elif campo == "nombres":
            self.nombres_valid = ok
        elif campo == "apellidos":
            self.apellidos_valid = ok
        elif campo == "departamento":
            self.departamento_valid = ok
        elif campo == "ciudad":
            self.ciudad_valid = ok
        return ok

    def validar_correo_accion(self):
        """Acción invocada por el botón 'Validar' junto al correo."""
        self.correo_validado = validar_correo(self.correo)
        if not self.correo_validado:
            self.error_de_registro = "Correo inválido."
        else:
            self.error_de_registro = ""
        return

    # Setters that also validate so we can show inline icons
    def set_and_validate_nombres(self, val: str):
        self.nombres = val
        self.validar_campo_simple("nombres")

    def set_and_validate_apellidos(self, val: str):
        self.apellidos = val
        self.validar_campo_simple("apellidos")

    def set_and_validate_numero_identificacion(self, val: str):
        self.numero_identificacion = val
        self.validar_campo_simple("numero_identificacion")

    def set_and_validate_telefono(self, val: str):
        self.telefono = val
        self.validar_campo_simple("telefono")

    def set_and_validate_departamento(self, val: str):
        self.departamento = val
        self.ciudad = ""  # Limpia la ciudad cuando cambia el departamento
        self.validar_campo_simple("departamento")

    def set_and_validate_ciudad(self, val: str):
        self.ciudad = val
        self.validar_campo_simple("ciudad")

    def set_and_validate_correo(self, val: str):
        """Valida el correo en tiempo real y borra el mensaje si es válido o vacío."""
        self.correo = val or ""
        # Limpiar mensaje de éxito cuando el usuario comienza a escribir
        self.succes = ""
        
        # Si el correo está vacío, borra el mensaje
        if not self.correo.strip():
            self.correo_confirmacion_visible = False
            self.correo_confirmacion_mensaje = ""
            self.error_de_registro = ""
            self.correo_validado = False
            return
        
        # Si es válido, muestra mensaje verde y borra error
        if validar_correo(self.correo):
            self.correo_confirmacion_visible = True
            self.correo_confirmacion_mensaje = "Correo válido."
            self.error_de_registro = ""
            self.correo_validado = True
        else:
            # Si es inválido, muestra mensaje rojo
            self.correo_confirmacion_visible = True
            self.correo_confirmacion_mensaje = "Correo no válido."
            self.error_de_registro = "Correo no válido."
            self.correo_validado = False

    def set_etnia(self, val: str):
        self.etnia = val or ""

    def set_persona_vulnerable_registro(self, val: str):
        self.persona_vulnerable_registro = val or ""

    def set_modal_politica_visible(self, visible: bool):
        self.modal_politica_visible = bool(visible)

    def set_archivo_error_mensaje(self, mensaje: str):
        self.archivo_error_mensaje = mensaje or ""

    def set_correo_confirmacion_visible(self, visible: bool):
        self.correo_confirmacion_visible = bool(visible)

    def set_correo_confirmacion_mensaje(self, mensaje: str):
        self.correo_confirmacion_mensaje = mensaje or ""

    def set_descripcion(self, val: str):
        # Guardar descripción y longitud para el contador de caracteres
        self.descripcion = val if val is not None else ""
        # Limitar a 1000 caracteres en la UI
        if len(self.descripcion) > 1000:
            self.descripcion = self.descripcion[:1000]
        self.descripcion_len = len(self.descripcion)

    def set_tipo_solicitud(self, val: str):
        self.tipo_solicitud = val or ""

    def set_persona_vulnerable(self, val: str):
        self.persona_vulnerable = val or ""

    def set_asunto(self, val: str):
        self.asunto = val or ""

    def set_ubicacion(self, val: str):
        self.ubicacion = val or ""

    def set_acepta_politica_solicitud(self, checked: bool):
        self.acepta_politica_solicitud = bool(checked)

    def preconfirmar_politica(self, checked: bool):
        if checked:
            self.modal_politica_visible = True
        else:
            self.acepta_politica_datos = False

    def confirmar_politica(self):
        self.acepta_politica_datos = True
        self.modal_politica_visible = False

    def cancelar_politica(self):
        self.acepta_politica_datos = False
        self.modal_politica_visible = False

    def set_acepta_notificaciones(self, checked: bool):
        self.acepta_notificaciones = bool(checked)

    def set_documento(self, documento):
        """Gestiona la selección de archivos adjuntos con validación estricta."""
        import os
 
        # Extensiones y pesos permitidos
        ALLOWED_EXT   = {"pdf", "png", "jpg", "jpeg"}
        MAX_PER_FILE  = 10 * 1024 * 1024   # 10 MB por archivo
        MAX_TOTAL     = 10 * 1024 * 1024   # 10 MB en total
        MAX_FILES     = 3
 
        self.archivo_error_mensaje = ""
 
        # ── Helpers ───────────────────────────────────────────────────────────
        def get_name(item) -> str:
            if isinstance(item, dict):
                return item.get("name") or item.get("filename") or "adjunto"
            if isinstance(item, str):
                return os.path.basename(item)
            return "adjunto"
 
        def get_size(item) -> int:
            if isinstance(item, dict):
                return int(item.get("size") or 0)
            return 0
 
        def get_ext(name: str) -> str:
            return os.path.splitext(name)[1].lower().lstrip(".")
 
        # ── Normalizar entrada a lista ─────────────────────────────────────────
        archivos_nuevos = documento if isinstance(documento, list) else [documento]
 
        # ── Construir set de (nombre, tamaño) ya existentes para deduplicar ───
        existentes = {
            (get_name(item), get_size(item))
            for item in self.documentos
        }
 
        candidatos = []
        for item in archivos_nuevos:
            nombre = get_name(item)
            tamano = get_size(item)
            llave  = (nombre, tamano)
 
            # 1. Duplicado
            if llave in existentes:
                continue
 
            # 2. Extensión no permitida
            ext = get_ext(nombre)
            if ext not in ALLOWED_EXT:
                self.archivo_error_mensaje = (
                    f"'{nombre}' No es válido. "
                    "Solo se permiten archivos PDF, PNG o JPG."
                )
                return   # cortar en el primer error de tipo
 
            # 3. Peso individual
            if tamano > MAX_PER_FILE:
                mb = tamano / (1024 * 1024)
                self.archivo_error_mensaje = (
                    f"'{nombre}' pesa {mb:.1f} MB. "
                    "El límite por archivo es 10 MB."
                )
                return
 
            candidatos.append(item)
            existentes.add(llave)
 
        # Si no hay candidatos nuevos válidos, salir sin cambiar nada
        if not candidatos:
            return
 
        # 4. Límite de cantidad total
        if len(self.documentos) + len(candidatos) > MAX_FILES:
            self.archivo_error_mensaje = (
                f"Solo puedes adjuntar hasta {MAX_FILES} archivos. "
                f"Ya tienes {len(self.documentos)}."
            )
            return
 
        # 5. Límite de peso total acumulado
        peso_actual   = sum(get_size(i) for i in self.documentos)
        peso_nuevos   = sum(get_size(i) for i in candidatos)
        if peso_actual + peso_nuevos > MAX_TOTAL:
            total_mb = (peso_actual + peso_nuevos) / (1024 * 1024)
            self.archivo_error_mensaje = (
                f"El peso total superaría {total_mb:.1f} MB. "
                "El límite acumulado es 10 MB."
            )
            return
 
        # ── Agregar candidatos válidos ─────────────────────────────────────────
        nuevos_docs    = list(self.documentos)
        nuevos_nombres = list(self.documento_nombres)
 
        for item in candidatos:
            nombre = get_name(item)
            nuevos_docs.append(item)
            nuevos_nombres.append(nombre)
 
        self.documentos        = nuevos_docs
        self.documento_nombres = nuevos_nombres
        self.documento_nombre  = ", ".join(self.documento_nombres)
        self.archivo_error_mensaje = ""
 
    def set_editar_solicitud_id(self, id: int):
        self.editar_solicitud_id = id

    def set_eliminar_solicitud_id(self, id: int):
        self.eliminar_solicitud_id = id

    def quitar_documento(self, nombre_archivo_a_eliminar: str):
        """Lógica para eliminar el archivo y limpiar las 3 variables de estado."""
        
        # 1. Filtrar la lista de objetos y la lista de nombres
        nuevos_docs = []
        nuevos_nombres = []
        
        for i, doc in enumerate(self.documentos):
            nombre_actual = self.documento_nombres[i]
            if nombre_actual != nombre_archivo_a_eliminar:
                nuevos_docs.append(doc)
                nuevos_nombres.append(nombre_actual)
        
        # 2. Reasignar las listas (esto dispara la actualización visual)
        self.documentos = nuevos_docs
        self.documento_nombres = nuevos_nombres
        
        # 3. Actualizar el string unido por comas
        self.documento_nombre = ", ".join(self.documento_nombres)
        
        # 4. Limpiar errores para que el mensaje rojo desaparezca
        self.archivo_error_mensaje = ""

    def eliminar_documento_por_nombre(self, nombre: str):
        self.quitar_documento(nombre)

    def confirmar_editar_solicitud(self):
        if self.editar_solicitud_id:
            self.editar_solicitud(self.editar_solicitud_id)
            self.editar_solicitud_id = 0

    def confirmar_eliminar_solicitud(self):
        if self.eliminar_solicitud_id:
            self.eliminar_solicitud(self.eliminar_solicitud_id)
            self.eliminar_solicitud_id = 0

    def set_area_responsable(self, val: str):
        self.area_responsable = val
        if val != "Otros":
            self.area_otro = ""

    def set_area_otro(self, val: str):
        self.area_otro = val

    def set_nuevo_estado(self, val: str):
        self.nuevo_estado = val

    def set_respuesta_solicitud(self, val: str):
        self.respuesta_solicitud = val

    def set_respuesta_documento(self, documento: Any):
        """Actualiza el documento adjunto en la respuesta del funcionario."""
        if isinstance(documento, dict):
            name = documento.get("name") or documento.get("filename") or "respuesta_adjunto"
            self.respuesta_documento_nombre = name
            self.respuesta_documento = documento
        elif isinstance(documento, str):
            self.respuesta_documento_nombre = os.path.basename(documento)
            self.respuesta_documento = documento
        else:
            self.respuesta_documento_nombre = ""
            self.respuesta_documento = documento

    def set_asignar_area_mensaje(self, val: str):
        self.asignar_area_mensaje = val

    def set_asignar_area_seleccionada(self, val: str):
        self.asignar_area_seleccionada = val or ""

    def set_asignar_area_nombre(self, val: str):
        self.asignar_area_nombre = val or ""

    def cerrar_editor_estado(self):
        self.editar_estado_id = 0
        self.nuevo_estado = ""
        self.respuesta_solicitud = ""
        self.respuesta_documento = ""
        self.respuesta_documento_nombre = ""
        self.mensaje_actualizar_estado = ""

    def set_consulta_radicado(self, val: str):
        self.consulta_radicado = val

    def actualizar_estado_solicitud(self):
        """Actualiza el estado de una solicitud con validación para cerrada."""
        self.mensaje_actualizar_estado = ""
        
        if not self.editar_estado_id or not self.nuevo_estado:
            self.mensaje_actualizar_estado = "Selecciona un estado válido."
            return
        
        # Validar que si se quiere cerrar, debe haber respuesta
        if self.nuevo_estado == "Cerrada" and not self.respuesta_solicitud:
            self.mensaje_actualizar_estado = "No puedes cerrar una solicitud sin escribir una respuesta."
            return
        
        # Guardar documento de respuesta si existe
        documento_respuesta_guardado = ""
        if self.respuesta_documento:
            try:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                # Caso: data URL (base64)
                if isinstance(self.respuesta_documento, str) and self.respuesta_documento.startswith("data:"):
                    header, b64 = self.respuesta_documento.split(",", 1)
                    mime = header.split(";")[0].split(":")[1] if ":" in header else ""
                    ext = mime.split("/")[-1] if "/" in mime else "bin"
                    saved_name = f"respuesta_{uuid.uuid4().hex}.{ext}"
                    path = os.path.join(UPLOAD_DIR, saved_name)
                    with open(path, "wb") as f:
                        f.write(base64.b64decode(b64))
                    documento_respuesta_guardado = path
                # Caso: objeto con 'content' y 'name'
                elif isinstance(self.respuesta_documento, dict) and "content" in self.respuesta_documento:
                    content = self.respuesta_documento.get("content")
                    name = self.respuesta_documento.get("name", f"respuesta_{uuid.uuid4().hex}")
                    # Sanitizar nombre de archivo
                    name = sanitizar_nombre_archivo(name)
                    if isinstance(content, str) and content.startswith("data:"):
                        _, b64 = content.split(",", 1)
                        data = base64.b64decode(b64)
                    else:
                        data = base64.b64decode(content)
                    path = os.path.join(UPLOAD_DIR, name)
                    with open(path, "wb") as f:
                        f.write(data)
                    documento_respuesta_guardado = path
                else:
                    # Si viene solo el nombre o ruta, lo conservamos tal cual
                    documento_respuesta_guardado = str(self.respuesta_documento)
            except Exception as e:
                print(f"Error guardando documento de respuesta: {e}")
                # Continuamos sin guardar el documento
        
        try:
            with Session(engine) as session:
                solicitud_obj = session.get(Solicitud, self.editar_estado_id)
                if not solicitud_obj:
                    self.mensaje_actualizar_estado = "Solicitud no encontrada."
                    return
                
                solicitud_obj.estado = self.nuevo_estado
                if self.respuesta_solicitud:
                    solicitud_obj.respuesta = self.respuesta_solicitud
                
                # Guardar documento de respuesta si existe
                if documento_respuesta_guardado:
                    # Si la solicitud no tiene campo para respuesta_documento, lo agregamos como metadato en respuesta
                    solicitud_obj.respuesta = (solicitud_obj.respuesta or "") + f"\n\n[DOCUMENTO ADJUNTO: {os.path.basename(documento_respuesta_guardado)}]"
                
                session.add(solicitud_obj)
                session.commit()
            
            solicitud_id = self.editar_estado_id
            estado_enviado = self.nuevo_estado
            respuesta_enviada = self.respuesta_solicitud
            self.mensaje_actualizar_estado = f"Estado actualizado a '{estado_enviado}' correctamente."
            self.editar_estado_id = 0
            self.nuevo_estado = ""
            self.respuesta_solicitud = ""
            self.respuesta_documento = ""
            self.respuesta_documento_nombre = ""
            self.cargar_solicitudes()
            
            # Enviar notificación por correo al ciudadano
            try:
                # Obtener información de la solicitud y el ciudadano
                solicitud_info = None
                for sol in self.solicitudes:
                    if sol['id'] == solicitud_id:
                        solicitud_info = sol
                        break
                
                if solicitud_info:
                    asunto_email = f"Actualización en tu solicitud PQRS - {solicitud_info['radicado']}"
                    cuerpo_email = f"""
Estimado ciudadano,

Tu solicitud PQRS con número de radicado {solicitud_info['radicado']} ha sido actualizada.

Detalles de la solicitud:
- Tipo: {solicitud_info['tipo_solicitud']}
- Asunto: {solicitud_info['asunto']}
- Estado actual: {estado_enviado}
- Fecha de actualización: {datetime.now().strftime('%Y-%m-%d %H:%M')}

"""
                    if respuesta_enviada:
                        cuerpo_email += f"Respuesta del funcionario:\n{respuesta_enviada}\n\n"
                    
                    if documento_respuesta_guardado:
                        doc_name = os.path.basename(documento_respuesta_guardado)
                        host_url = os.getenv("APP_URL", "http://localhost:3000").rstrip("/")
                        doc_url = f"{host_url}/assets/uploads/{doc_name}"
                        cuerpo_email += f"Documento adjunto: {doc_name}\nDescarga: {doc_url}\n\n"
                    
                    cuerpo_email += """
Puedes consultar el estado completo de tu solicitud en nuestro portal web.

Atentamente,
Equipo de Atención al Ciudadano
Sistema PQRS
"""
                    
                    # Enviar correo al ciudadano
                    enviar_correo_notificacion(solicitud_info['creado_por'], asunto_email, cuerpo_email)
                    
            except Exception as e:
                print(f"Error enviando notificación: {e}")
                # No fallar la actualización por error en notificación
        except Exception as e:
            self.mensaje_actualizar_estado = f"Error actualizando estado: {e}"

    def abrir_editor_estado(self, solicitud_id: int, estado_actual: str):
        """Abre el editor de estado para una solicitud."""
        self.editar_estado_id = solicitud_id
        self.nuevo_estado = estado_actual
        self.respuesta_solicitud = ""
        self.respuesta_documento = ""
        self.respuesta_documento_nombre = ""
        self.mensaje_actualizar_estado = ""

    def abrir_asignar_area(self, solicitud_id: int, area_actual: str):
        """Abre el diálogo para asignar un área a una solicitud con mensaje."""
        self.asignar_area_id = solicitud_id
        self.asignar_area_nombre = area_actual
        self.asignar_area_seleccionada = area_actual or "Atención al Ciudadano"
        self.asignar_area_mensaje = ""
        self.mensaje_asignacion = ""

    def cerrar_asignar_area(self):
        """Cierra el diálogo de asignación de área."""
        self.asignar_area_id = 0
        self.asignar_area_nombre = ""
        self.asignar_area_seleccionada = ""
        self.asignar_area_mensaje = ""
        self.mensaje_asignacion = ""

    def asignar_area_con_mensaje(self):
        """Asigna un área a una solicitud y envía un mensaje al ciudadano."""
        self.mensaje_asignacion = ""
        
        area_a_asignar = self.asignar_area_seleccionada or self.asignar_area_nombre
        if not self.asignar_area_id or not area_a_asignar:
            self.mensaje_asignacion = "Selecciona un área válida."
            return
        
        if not self.asignar_area_mensaje:
            self.mensaje_asignacion = "Escribe un mensaje para el ciudadano."
            return
        
        try:
            with Session(engine) as session:
                solicitud_obj = session.get(Solicitud, self.asignar_area_id)
                if not solicitud_obj:
                    self.mensaje_asignacion = "Solicitud no encontrada."
                    return
                
                solicitud_obj.area_responsable = area_a_asignar
                session.add(solicitud_obj)
                session.commit()
            
            # Enviar notificación por correo al ciudadano
            solicitud_info = None
            for sol in self.solicitudes:
                if sol['id'] == self.asignar_area_id:
                    solicitud_info = sol
                    break
            
            if solicitud_info:
                area_a_asignar = self.asignar_area_seleccionada or self.asignar_area_nombre
                asunto_email = f"Tu solicitud PQRS ha sido asignada a {area_a_asignar}"
                cuerpo_email = f"""
Estimado ciudadano,

Tu solicitud PQRS con número de radicado {solicitud_info['radicado']} ha sido asignada a {area_a_asignar} para su tratamiento.

Detalles de la solicitud:
- Tipo: {solicitud_info['tipo_solicitud']}
- Asunto: {solicitud_info['asunto']}
- Área responsable: {area_a_asignar}

Mensaje del funcionario:
{self.asignar_area_mensaje}

Puedes consultar el estado completo de tu solicitud en nuestro portal web.

Atentamente,
Equipo de Atención al Ciudadano
Sistema PQRS
"""

                # Enviar correo al ciudadano
                enviar_correo_notificacion(solicitud_info['creado_por'], asunto_email, cuerpo_email)
            
            self.mensaje_asignacion = f"Área asignada a {area_a_asignar} y mensaje enviado correctamente."
            self.cargar_solicitudes()
            self.cerrar_asignar_area()
        except Exception as e:
            self.mensaje_asignacion = f"Error asignando área: {e}"

    def _solicitud_a_dict(self, solicitud: Solicitud) -> dict[str, Any]:
        respuesta_text = solicitud.respuesta or ""
        respuesta_documento_basename = None
        if respuesta_text:
            match = re.search(r"\[DOCUMENTO ADJUNTO:\s*([^\]\|]+)\]", respuesta_text)
            if match:
                respuesta_documento_basename = match.group(1).strip()
                respuesta_text = re.sub(r"\s*\[DOCUMENTO ADJUNTO:[^\]]+\]", "", respuesta_text).strip()

        documento_basenames = []
        if solicitud.documento_basename:
            try:
                parsed_names = json.loads(solicitud.documento_basename)
                if isinstance(parsed_names, list):
                    documento_basenames = parsed_names
                else:
                    documento_basenames = [parsed_names]
            except Exception:
                documento_basenames = [solicitud.documento_basename]

        documento_paths = []
        if solicitud.documento:
            try:
                parsed_paths = json.loads(solicitud.documento)
                if isinstance(parsed_paths, list):
                    documento_paths = parsed_paths
                else:
                    documento_paths = [parsed_paths]
            except Exception:
                documento_paths = [solicitud.documento]

        documento_adjuntos = []
        for idx, path in enumerate(documento_paths):
            basename = documento_basenames[idx] if idx < len(documento_basenames) else os.path.basename(str(path))
            documento_adjuntos.append(
                {
                    "basename": basename,
                    "href": f"/assets/uploads/{quote(basename)}" if basename else "",
                }
            )

        documento_basename = documento_adjuntos[0]["basename"] if documento_adjuntos else ""
        documento_href = documento_adjuntos[0]["href"] if documento_adjuntos else ""

        return {
            "id": solicitud.id,
            "radicado": solicitud.radicado,
            "tipo_solicitud": solicitud.tipo_solicitud,
            "persona_vulnerable": solicitud.persona_vulnerable,
            "asunto": solicitud.asunto,
            "descripcion": solicitud.descripcion,
            "ubicacion": solicitud.ubicacion,
            "area_responsable": solicitud.area_responsable,
            "documento": solicitud.documento,
            "documento_basename": documento_basename,
            "documento_href": documento_href,
            "documento_adjuntos": documento_adjuntos,
            "documento_adjuntos_json": json.dumps(documento_adjuntos),
            "estado": solicitud.estado,
            "respuesta": respuesta_text,
            "respuesta_documento_basename": respuesta_documento_basename,
            "respuesta_documento_href": f"/assets/uploads/{quote(respuesta_documento_basename)}" if respuesta_documento_basename else "",
            "fecha": solicitud.fecha.strftime("%Y-%m-%d %H:%M") if isinstance(solicitud.fecha, datetime) else str(solicitud.fecha),
            "creado_por": solicitud.creado_por,
           "usuario_id": solicitud.usuario_id,
        
        
        }
        

        # Extraer metadata embebida en `documento` si existe (usado para pruebas/seed)
        try:
            if solicitud.documento:
                parsed = json.loads(solicitud.documento)
                if isinstance(parsed, dict):
                    if "tiempo_respuesta_dias" in parsed:
                        result["tiempo_respuesta_dias"] = parsed.get("tiempo_respuesta_dias")
                    if "fecha_respuesta" in parsed:
                        result["fecha_respuesta"] = parsed.get("fecha_respuesta")
                    if "cumple_plazo" in parsed:
                        result["cumple_plazo"] = parsed.get("cumple_plazo")
        except Exception:
            pass

        return result
        
        

    @rx.var
    def solicitud_consultada_adjuntos(self) -> list[dict[str, str]]:
        docs = self.solicitud_consultada.get("documento_adjuntos", [])
        if not isinstance(docs, list):
            return []

        resultado = []
        for doc in docs:
            if isinstance(doc, dict):
                resultado.append({
                    "basename": str(doc.get("basename", "")),
                    "href": str(doc.get("href", "")),
                })
        return resultado

    def cargar_solicitudes(self):
        try:
            with rx.session() as session:
                # Ordenar por fecha descendente para mostrar las más nuevas primero
                query = select(Solicitud).order_by(Solicitud.fecha.desc())
                if self.rol_usuario == "ciudadano" and self.email_actual:
                    query = query.where(Solicitud.creado_por == self.email_actual)
                solicitudes_obj = session.exec(query).all()
                self.solicitudes = [self._solicitud_a_dict(s) for s in solicitudes_obj]
                # Precompute semáforo values per solicitud to ensure reliable rendering
                # Fetch DB-stored fecha_respuesta (if any) into each solicitud dict so charts can use it
                with engine.connect() as conn:
                    for s in self.solicitudes:
                        try:
                            row = conn.execute(text("SELECT fecha_respuesta FROM solicitud WHERE id = :id"), {"id": s.get('id')}).fetchone()
                            if row and row[0]:
                                # store raw DB value (string/datetime)
                                s['fecha_respuesta'] = str(row[0])
                            else:
                                s['fecha_respuesta'] = None
                        except Exception:
                            s['fecha_respuesta'] = None

                for s in self.solicitudes:
                    try:
                        sem = State._compute_remaining_for_solicitud(s)
                        s['semaforo_remaining'] = sem.get('remaining')
                        s['semaforo_fill'] = sem.get('fill')
                        print(f"DEBUG - semaforo for {s.get('radicado')} => {s['semaforo_fill']} / {s['semaforo_remaining']}")
                    except Exception as e:
                        print(f"DEBUG - semaforo compute error for {s.get('radicado')}: {e}")
                        s['semaforo_remaining'] = None
                        s['semaforo_fill'] = 'gray'
                # Diagnostics: print data structures used by charts
                print("DEBUG - cargar_solicitudes - data_grafica_tipo:", self.data_grafica_tipo)
                print("DEBUG - cargar_solicitudes - monthly_response_times:", self.monthly_response_times)
                print("DEBUG - cargar_solicitudes - compliance_chart_data:", self.compliance_chart_data)
                print("DEBUG - cargar_solicitudes - semaforo_counts:", self.semaforo_counts)
                print("DEBUG - cargar_solicitudes - semaforo_chart_data:", self.semaforo_chart_data)

        except Exception as e:
            print(f"Error cargando solicitudes: {e}")
            self.solicitudes = []

    def export_reportes_excel(self):
        """Genera un Excel en memoria desde `self.solicitudes` para descarga.
        
        Si pandas no está disponible, genera un CSV como fallback.
        """
        try:
            import io
            from datetime import datetime

            data = self.solicitudes or []
            if not data:
                self.mostrar_toast("No hay datos para exportar.", "warning")
                self.mostrar_menu_descarga = False
                return
            
            # Intentar con Excel primero
            try:
                import pandas as pd
                print(f"DEBUG: Generando Excel en memoria con {len(data)} registros")
                
                df = pd.DataFrame(data)
                
                # Usar BytesIO para guardar en memoria
                output = io.BytesIO()
                df.to_excel(output, index=False, sheet_name="Solicitudes", engine="openpyxl")
                output.seek(0)
                
                excel_bytes = output.getvalue()
                filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.xlsx"
                download_id = str(uuid.uuid4())
                
                TEMP_DOWNLOADS[download_id] = {
                    "data": excel_bytes,
                    "filename": filename,
                    "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                }
                
                self.export_filename = filename
                self.mostrar_toast(f"✓ Excel generado. {len(data)} registros. Descargando...", "success")
                self.mostrar_menu_descarga = False
                self.export_href = f"/api/download/{download_id}"
                
            except (ImportError, ModuleNotFoundError) as e:
                print(f"DEBUG: pandas no disponible, usando CSV: {e}")
                # Fallback a CSV
                self.export_reportes_csv()
                
        except Exception as e:
            print(f"ERROR CRITICO en export_reportes_excel: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.mostrar_toast(f"Error: {str(e)[:100]}", "error")
            self.mostrar_menu_descarga = False


    def descargar_reporte_excel(self):
        """Descarga el archivo Excel generado."""
        try:
            if not self.export_filename:
                self.mostrar_toast("No hay archivo para descargar.", "warning")
                return
            
            filepath = os.path.join(UPLOAD_DIR, self.export_filename)
            print(f"DEBUG: Intentando descargar {filepath}")
            
            if not os.path.exists(filepath):
                self.mostrar_toast(f"Archivo no encontrado: {self.export_filename}", "error")
                self.export_filename = ""
                self.export_href = ""
                return
            
            # Leer el archivo y preparar para descarga
            with open(filepath, 'rb') as f:
                content = f.read()
            
            print(f"DEBUG: Archivo leído. Tamaño: {len(content)} bytes")
            
            # Usar rx.download para forzar la descarga
            return rx.download(
                data=content,
                filename=self.export_filename,
                mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            
        except Exception as e:
            print(f"ERROR en descargar_reporte_excel: {e}")
            import traceback
            traceback.print_exc()
            self.mostrar_toast(f"Error descargando: {str(e)}", "error")

    def _validar_registro_basico(self) -> None:
        self.error_de_registro = ""
        
        # Validar entrada de credenciales, correo confirmado y contraseña
        if not self.validacion_de_entradas():
            return
        
        # Validar que todos los campos de información personal estén completos
        required_fields = ["nombres", "apellidos", "tipo_identificacion", "numero_identificacion", "telefono", "departamento", "ciudad"]
        for f in required_fields:
            field_value = getattr(self, f, "")
            if not field_value or (isinstance(field_value, str) and not field_value.strip()):
                self.error_de_registro = f"El campo '{f}' es obligatorio. Completa todos los campos requeridos."
                return
        
        # Validar que las autorizaciones sean aceptadas
        if not self.acepta_politica_datos:
            self.error_de_registro = "Debes aceptar la Política de Protección de Datos para continuar."
            return
        
        if not self.acepta_notificaciones:
            self.error_de_registro = "Debes autorizar las notificaciones por correo electrónico para continuar."
            return

    def _crear_usuario(self, rol: str, exito_mensaje: str):
        with rx.session() as session:
            existing_user = session.exec(select(Usuario).where(Usuario.email == self.correo)).first()
            if existing_user:
                self.error_de_registro = "El correo ya está registrado."
                return
            hashed = tiene_password(self.contraseña)
            nuevo_usuario = Usuario(
                email=self.correo,
                Contraseña=hashed,
                rol=rol,
                is_active=True,
                Fecha_de_creacion=datetime.now(),
                tipo_identificacion=self.tipo_identificacion,
                numero_identificacion=self.numero_identificacion,
                nombres=self.nombres,
                apellidos=self.apellidos,
                sexo=self.sexo,
                direccion=self.direccion,
                telefono=self.telefono,
                departamento=self.departamento,
                ciudad=self.ciudad,
                etnia=self.etnia,
                persona_vulnerable=self.persona_vulnerable_registro,
            )
            session.add(nuevo_usuario)
            session.commit()
        print(f"Usuario registrado: {self.correo}")
        enviar_correo_bienvenida(self.correo, self.correo)
        self.succes = exito_mensaje
        self.mostrar_toast("¡Registro exitoso! Bienvenido al sistema.", "success")
        # Guardar el correo antes de limpiar el formulario
        correo_registrado = self.correo
        # Limpiar todos los campos del formulario (incluyendo el mensaje de éxito después de un breve delay)
        self.limpiar_formulario_registro()
        # Login automático después del registro
        self.es_autentica = True
        self.correo_usuario = correo_registrado
        self.rol_usuario = "ciudadano"
        self.cargar_usuarios()

    def signup(self):
        self.borrar_mensajes_de_estado()
        self._validar_registro_basico()
        if self.error_de_registro:
            return
        self._crear_usuario(
            rol="ciudadano",
            exito_mensaje="Registro exitoso. Revisa tu correo para confirmar. Ahora el funcionario puede iniciar sesión.",
        )
        # Redirigir a solicitudes después del registro
        if not self.error_de_registro:
            return rx.redirect("/solicitudes")

    def signup_funcionario(self):
        self.borrar_mensajes_de_estado()
        if not self.es_autentica or self.rol_usuario != "funcionario":
            self.error_de_registro = "Solo los funcionarios autenticados pueden registrar nuevos funcionarios."
            return
        self._validar_registro_basico()
        if self.error_de_registro:
            return
        return self._crear_usuario(
            rol="funcionario",
            exito_mensaje="Funcionario registrado con éxito. Ahora puede iniciar sesión con su correo institucional.",
        )

    def login(self):
        self.borrar_mensajes_de_estado()
        if not self.validacion_login():
            self.succes2 = ""
            self.error_de_contraseña = self.error_de_registro or "Correo o contraseña incorrectos."
            self.error_de_registro = ""
            return
        with Session(engine) as session:
            user = session.exec(select(Usuario).where(Usuario.email == self.correo)).first()
            print(f"Login lookup for: {self.correo} -> {'FOUND' if user else 'NOT FOUND'}")
            if user:
                print(f"  stored hash present: {bool(user.Contraseña)}")
            pw_ok = False
            try:
                pw_ok = confirmar_contraseña(self.contraseña, user.Contraseña) if user else False
            except Exception as e:
                print(f"Error comprobando contraseña: {e}")
            print(f"Login attempt for: {self.correo}, success: {pw_ok}")
            if not user or not pw_ok:
                self.error_de_contraseña = "Correo o contraseña incorrectos."
                self.succes2 = ""
                return
            if not user.is_active:
                self.error_de_contraseña = "La cuenta no está activa."
                self.succes2 = ""
                return
            self.id_usuario = user.id
            self.rol_usuario = user.rol
            self.email_actual = user.email
            self.es_autentica = True
            self.cargar_solicitudes()
            self.cargar_usuarios()
            self.error_de_contraseña = ""
            self.contraseña = ""
            self.confirmar_contraseña = ""
            self.show_password = False
            return rx.toast.success(
                "¡Inicio de sesión exitoso!",
                duration=2500,
                description="Redirigiendo automáticamente...",
                on_auto_close=State.redirect_after_login,
            )
        

    def redirect_after_login(self):
        if self.rol_usuario == "funcionario":
            return rx.redirect("/dashboard-funcionario")
        return rx.redirect("/dashboard")

    def logout(self):
        "cerrar sesion de usuario"
        self.id_usuario = 0
        self.correo = ""
        self.contraseña = ""
        self.confirmar_contraseña = ""
        self.rol_usuario = ""
        self.email_actual = ""
        self.es_autentica = False
        self.show_password = False
        self.succes2 = "Has cerrado sesión exitosamente."
        self.error_de_contraseña = ""
        return rx.redirect("/")

    def change_password(self):
        """Cambiar la contraseña del usuario autenticado."""
        self.change_pw_message = ""
        if not self.es_autentica or not self.id_usuario:
            self.change_pw_message = "Debes iniciar sesión para cambiar la contraseña."
            return
        # Validaciones básicas
        if not self.current_password or not self.new_password or not self.confirm_new_password:
            self.change_pw_message = "Completa todos los campos."
            return
        if self.new_password != self.confirm_new_password:
            self.change_pw_message = "La nueva contraseña y su confirmación no coinciden."
            return
        if not cantida_minima_contraseña(self.new_password):
            self.change_pw_message = "La nueva contraseña no cumple los requisitos de seguridad."
            return
        with Session(engine) as session:
            user = session.exec(select(Usuario).where(Usuario.id == self.id_usuario)).first()
            if not user:
                self.change_pw_message = "Usuario no encontrado."
                return
            try:
                if not confirmar_contraseña(self.current_password, user.Contraseña):
                    self.change_pw_message = "La contraseña actual es incorrecta."
                    return
            except Exception as e:
                self.change_pw_message = f"Error comprobando contraseña: {e}"
                return
            # Actualizar contraseña
            user.Contraseña = tiene_password(self.new_password)
            session.add(user)
            session.commit()
            self.change_pw_message = "Contraseña cambiada correctamente."
            # Limpiar campos
            self.current_password = ""
            self.new_password = ""
            self.confirm_new_password = ""

    def toggle_show_password(self):
        self.show_password = not self.show_password

    def limpiar_formulario_solicitud(self, keep_message: bool = False):
        self.tipo_solicitud = ""
        self.persona_vulnerable = ""
        self.asunto = ""
        self.descripcion = ""
        self.ubicacion = ""
        self.documento = ""
        self.documentos = []
        self.documento_nombres = []
        self.documento_nombre = ""
        self.area_responsable = ""
        self.area_otro = ""
        self.descripcion_len = 0
        self.editar_solicitud_id = 0
        self.acepta_politica_solicitud = False
        if not keep_message:
            self.solicitud_mensaje = ""

    def crear_solicitud(self):
        self.solicitud_mensaje = ""
        if not self.tipo_solicitud or not self.asunto or not self.descripcion:
            self.solicitud_mensaje = "Completa los campos obligatorios antes de enviar."
            return
        if not self.area_responsable:
            self.solicitud_mensaje = "Selecciona el área responsable."
            return
        if self.area_responsable == "Otros" and not self.area_otro:
            self.solicitud_mensaje = "Por favor indica el área responsable cuando eliges Otros."
            return
        # Verificar aceptación de política de tratamiento de datos
        if not self.acepta_politica_solicitud:
            self.solicitud_mensaje = "Debes aceptar la Política de Tratamiento de Datos Personales antes de enviar."
            return

        documentos_guardados: list[str] = []
        documento_basenames_guardados: list[str] = []

        def guardar_archivo(item: Any) -> None:
            if isinstance(item, str) and not item.startswith("data:"):
                documentos_guardados.append(item)
                documento_basenames_guardados.append(os.path.basename(item))
                return

            if isinstance(item, str) and item.startswith("data:"):
                header, b64 = item.split(",", 1)
                mime = header.split(";")[0].split(":")[1] if ":" in header else ""
                ext = mime.split("/")[-1] if "/" in mime else "bin"
                saved_name = f"solicitud_{uuid.uuid4().hex}.{ext}"
                path = os.path.join(UPLOAD_DIR, saved_name)
                with open(path, "wb") as f:
                    f.write(base64.b64decode(b64))
                documentos_guardados.append(path)
                documento_basenames_guardados.append(saved_name)
                return

            if isinstance(item, dict) and "content" in item:
                content = item.get("content")
                name = item.get("name", f"solicitud_{uuid.uuid4().hex}")
                name = sanitizar_nombre_archivo(name)
                if isinstance(content, str) and content.startswith("data:"):
                    _, b64 = content.split(",", 1)
                    data = base64.b64decode(b64)
                else:
                    data = base64.b64decode(content)
                path = os.path.join(UPLOAD_DIR, name)
                with open(path, "wb") as f:
                    f.write(data)
                documentos_guardados.append(path)
                documento_basenames_guardados.append(name)
                return

            if isinstance(item, dict):
                name = item.get("name") or item.get("filename") or f"solicitud_{uuid.uuid4().hex}"
                name = sanitizar_nombre_archivo(name)
                documento_basenames_guardados.append(name)
                documentos_guardados.append(name)
                return

            documento_basenames_guardados.append(str(item))
            documentos_guardados.append(str(item))

        if self.documentos:
            try:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                for item in self.documentos:
                    guardar_archivo(item)
            except Exception as e:
                self.solicitud_mensaje = f"Error guardando documento: {e}"
                return
        elif self.documento:
            try:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                guardar_archivo(self.documento)
            except Exception as e:
                self.solicitud_mensaje = f"Error guardando documento: {e}"
                return

        if self.editar_solicitud_id:
            try:
                with Session(engine) as session:
                    solicitud_obj = session.get(Solicitud, self.editar_solicitud_id)
                    if not solicitud_obj:
                        self.solicitud_mensaje = "Solicitud no encontrada para editar."
                        return
                    # Obtener persona_vulnerable del usuario autenticado
                    usuario = session.get(Usuario, self.id_usuario)
                    persona_vulnerable_valor = usuario.persona_vulnerable if usuario else None
                    
                    solicitud_obj.tipo_solicitud = self.tipo_solicitud
                    solicitud_obj.persona_vulnerable = persona_vulnerable_valor or None
                    solicitud_obj.asunto = self.asunto
                    solicitud_obj.descripcion = self.descripcion
                    solicitud_obj.ubicacion = self.ubicacion or None
                    solicitud_obj.area_responsable = self.area_otro if self.area_responsable == "Otros" else self.area_responsable
                    if documentos_guardados:
                        solicitud_obj.documento = json.dumps(documentos_guardados)
                        solicitud_obj.documento_basename = json.dumps(documento_basenames_guardados)
                    solicitud_obj.estado = "Actualizada"
                    session.add(solicitud_obj)
                    session.commit()
                self.solicitud_mensaje = "Solicitud actualizada con éxito."
                self.editar_solicitud_id = 0
                self.limpiar_formulario_solicitud(keep_message=True)
                self.cargar_solicitudes()
                return
            except Exception as e:
                self.solicitud_mensaje = f"Error actualizando solicitud: {e}"
                return

        try:
            with rx.session() as session:
                # Obtener persona_vulnerable del usuario autenticado
                usuario = session.get(Usuario, self.id_usuario)
                persona_vulnerable_valor = usuario.persona_vulnerable if usuario else None
                
                solicitud_obj = Solicitud(
                    radicado=f"PQRS-{datetime.now().year}-{uuid.uuid4().hex[:8]}".upper(),
                    tipo_solicitud=self.tipo_solicitud,
                    persona_vulnerable=persona_vulnerable_valor or None,
                    asunto=self.asunto,
                    descripcion=self.descripcion,
                    ubicacion=self.ubicacion or None,
                    area_responsable=self.area_otro if self.area_responsable == "Otros" else self.area_responsable,
                    documento=json.dumps(documentos_guardados) if documentos_guardados else None,
                    documento_basename=json.dumps(documento_basenames_guardados) if documento_basenames_guardados else None,
                    estado="Radicada",
                    fecha=datetime.now(),
                    creado_por=self.email_actual or self.correo,
                    usuario_id=self.id_usuario if self.id_usuario else None,
                )
                session.add(solicitud_obj)
                session.commit()
                radicado_generado = solicitud_obj.radicado
                self.solicitud_mensaje = f"✅ Solicitud enviada con éxito. Radicado: {radicado_generado}"
                self.limpiar_formulario_solicitud(keep_message=True)
                self.cargar_solicitudes()
        except Exception as e:
            self.solicitud_mensaje = f"Error guardando solicitud: {e}"

    def editar_solicitud(self, solicitud_id: int):
        try:
            with Session(engine) as session:
                solicitud_obj = session.get(Solicitud, solicitud_id)
                if solicitud_obj:
                    self.editar_solicitud_id = solicitud_id
                    self.tipo_solicitud = solicitud_obj.tipo_solicitud
                    self.asunto = solicitud_obj.asunto
                    self.descripcion = solicitud_obj.descripcion
                    self.ubicacion = solicitud_obj.ubicacion or ""
                    self.area_responsable = solicitud_obj.area_responsable or ""
                    self.area_otro = solicitud_obj.area_responsable if solicitud_obj.area_responsable and solicitud_obj.area_responsable not in ["Secretaría", "Contabilidad", "Bienestar", "Tesorería", "Atención al Ciudadano"] else ""
                    self.persona_vulnerable = solicitud_obj.persona_vulnerable or ""
                    self.documento = solicitud_obj.documento or ""
                    self.solicitud_mensaje = "Editando solicitud. Actualiza los campos y guarda cambios."
                else:
                    self.solicitud_mensaje = "Solicitud no encontrada."
        except Exception as e:
            self.solicitud_mensaje = f"Error cargando solicitud: {e}"

    def consultar_estado_solicitud(self):
        """Consulta el estado de una solicitud por número de radicado."""
        self.consulta_mensaje = ""
        self.solicitud_consultada = {}
        
        if not self.consulta_radicado:
            self.consulta_mensaje = "Ingresa un número de radicado válido."
            return
        
        try:
            with Session(engine) as session:
                solicitud = session.exec(
                    select(Solicitud).where(Solicitud.radicado == self.consulta_radicado)
                ).first()
                
                if not solicitud:
                    self.consulta_mensaje = "No se encontró una solicitud con ese número de radicado."
                    return
                
                self.solicitud_consultada = self._solicitud_a_dict(solicitud)
                self.consulta_mensaje = "Solicitud encontrada."
                
        except Exception as e:
            self.consulta_mensaje = f"Error consultando solicitud: {e}"

    def cargar_usuarios(self):
        """Carga la lista de usuarios registrados en el sistema."""
        try:
            with rx.session() as session:
                usuarios = session.exec(select(Usuario)).all()
                self.usuarios_registrados = [
                    {
                        "id": u.id,
                        "email": u.email,
                        "nombres": u.nombres or "",
                        "apellidos": u.apellidos or "",
                        "rol": u.rol,
                        "fecha_creacion": u.Fecha_de_creacion.strftime("%Y-%m-%d") if isinstance(u.Fecha_de_creacion, datetime) else str(u.Fecha_de_creacion),
                        "is_active": "Activo" if u.is_active else "Inactivo",
                    }
                    for u in usuarios
                ]
        except Exception as e:
            print(f"Error cargando usuarios: {e}")
            self.usuarios_registrados = []

    def cambiar_rol_ciudadano_a_funcionario(self):
        """Cambia el rol de un ciudadano a funcionario."""
        self.cambiar_rol_mensaje = ""
        
        if not self.cambiar_rol_email:
            self.cambiar_rol_mensaje = "Ingresa el correo del usuario."
            return
        
        try:
            with rx.session() as session:
                usuario = session.exec(
                    select(Usuario).where(Usuario.email == self.cambiar_rol_email)
                ).first()
                
                if not usuario:
                    self.cambiar_rol_mensaje = f"No se encontró usuario con el correo {self.cambiar_rol_email}."
                    return
                
                if usuario.rol == "funcionario":
                    self.cambiar_rol_mensaje = f"El usuario ya es funcionario."
                    return
                
                usuario.rol = "funcionario"
                session.add(usuario)
                session.commit()
                
                # Enviar notificación
                try:
                    asunto = "Rol actualizado - Has sido promovido a Funcionario"
                    cuerpo = f"""
Estimado usuario,

Te informamos que tu rol en el sistema ha sido actualizado.

Tu nuevo rol: FUNCIONARIO

Con este rol podrás:
- Gestionar solicitudes PQRS
- Asignar áreas responsables
- Actualizar estados de solicitudes
- Ver reportes del sistema

Accede al Dashboard Funcionario con tu correo y contraseña.

Atentamente,
Sistema PQRS
"""
                    enviar_correo_notificacion(self.cambiar_rol_email, asunto, cuerpo)
                except:
                    pass  # No fallar si no se envía el correo
                
                self.cambiar_rol_mensaje = f"✅ Rol del usuario {self.cambiar_rol_email} actualizado a funcionario."
                self.cambiar_rol_email = ""
                self.cargar_usuarios()
        except Exception as e:
            self.cambiar_rol_mensaje = f"Error al cambiar rol: {e}"

    def set_cambiar_rol_email(self, value: str):
        self.cambiar_rol_email = value


    def set_confirmar_contraseña(self, value: str):
        self.confirmar_contraseña = value

    def set_correo(self, value: str):
        self.correo = value

    def set_contraseña(self, value: str):
        self.contraseña = value

    def set_tipo_identificacion(self, value: str):
        self.tipo_identificacion = value

    def set_genero(self, value: str):
        self.genero = value

    def set_sexo(self, value: str):
        self.sexo = value

    def set_direccion(self, value: str):
        self.direccion = value

    def set_current_password(self, value: str):
        self.current_password = value


    """The app state."""
def label_requerido(texto: str) -> rx.Component:
    return rx.hstack(
        rx.text(texto, color=rx.color_mode_cond(light="black", dark="white")),
        rx.text("*", color="orange.500"),
        spacing="1",
        align_items="center",
    )

def auth_card(title: str, on_submit, show_confirm: bool = False) -> rx.Component:
    text_color = rx.color_mode_cond(light="black", dark="white")
    input_bg = rx.color_mode_cond(light="white", dark="#2d3748")
    input_border = rx.color_mode_cond(light="#cbd5e1", dark="#4a5568")
    placeholder_color = rx.color_mode_cond(light="#718096", dark="#a0aec0")

    input_style = {
        "bg": input_bg,
        "border": f"1px solid {input_border}",
        "color": text_color,
        "_placeholder": {"color": placeholder_color},
    }

    confirmar_field = (
        rx.vstack(
            label_requerido("Confirmar Contraseña"),
            rx.input(
                placeholder="Confirmar Contraseña",
                type=rx.cond(State.show_password, "text", "password"),
                value=State.confirmar_contraseña,
                on_change=State.set_confirmar_contraseña,
                border_radius="md",
                size="3",
                **input_style,
            ),
        )
        if show_confirm
        else rx.box(display="none")
    )

    return rx.card(
        rx.form(
            rx.vstack(
                rx.heading(title, size={"base": "5", "md": "7"}, color=text_color, margin_bottom="1em"),
                rx.grid(
                    rx.vstack(
                        label_requerido("Correo electrónico"),
                        rx.hstack(
                            rx.input(
                                placeholder="Correo electrónico",
                                type="email",
                                value=State.correo,
                                on_change=State.set_and_validate_correo,
                                on_blur=State.validar_correo_accion,
                                border_radius="md",
                                size="3",
                                width="100%",
                                **input_style,
                            ),
                            rx.cond(
                                State.correo_validado,
                                rx.image(src="/check-green.svg", height="16px", ml="2"),
                                rx.box(),
                            ),
                            width="100%",
                        ),
                        rx.cond(
                            State.correo_confirmacion_visible,
                            rx.text(
                                State.correo_confirmacion_mensaje,
                                color=rx.cond(State.correo_validado, "green.500", "red.500"),
                                font_size="sm",
                                mt="2",
                            ),
                            rx.box(),
                        ),
                    ),
                    rx.vstack(
                        label_requerido("Contraseña"),
                        rx.hstack(
                            rx.input(
                                placeholder="Contraseña",
                                type=rx.cond(State.show_password, "text", "password"),
                                value=State.contraseña,
                                on_change=State.set_contraseña,
                                border_radius="10px",
                                width="100%",
                                size="3",
                                **input_style,
                            ),
                            rx.button(
                                rx.cond(State.show_password, rx.icon("eye_off"), rx.icon("eye")),
                                on_click=State.toggle_show_password,
                                variant="ghost",
                                size="3",
                            ),
                            width="100%",
                            spacing="2",
                        ),
                        col_span="2",
                    ),
                    confirmar_field,
                    rx.vstack(
                        rx.text("Tipo de Identificación", font_weight="semibold", color=text_color),
                        rx.select(
                            ["Cédula", "Pasaporte", "Tarjeta de Identidad"],
                            placeholder="Selecciona",
                            value=State.tipo_identificacion,
                            on_change=State.set_tipo_identificacion,
                            border_radius="md",
                            **input_style,
                        ),
                    ),
                    rx.vstack(
                        label_requerido("Número de Identificación"),
                        rx.hstack(
                            rx.input(
                                placeholder="Número de Identificación",
                                value=State.numero_identificacion,
                                on_change=State.set_and_validate_numero_identificacion,
                                border_radius="md",
                                **input_style,
                            ),
                            rx.cond(
                                State.numero_identificacion_valid,
                                rx.image(src="/check-green.svg", height="16px", ml="2"),
                                rx.box(),
                            ),
                        ),
                    ),
                    rx.vstack(
                        label_requerido("Nombres"),
                        rx.hstack(
                            rx.input(
                                placeholder="Nombres",
                                value=State.nombres,
                                on_change=State.set_and_validate_nombres,
                                border_radius="md",
                                **input_style,
                            ),
                            rx.cond(
                                State.nombres_valid,
                                rx.image(src="/check-green.svg", height="16px", ml="2"),
                                rx.box(),
                            ),
                        ),
                    ),
                    rx.vstack(
                        label_requerido("Apellidos"),
                        rx.hstack(
                            rx.input(
                                placeholder="Apellidos",
                                value=State.apellidos,
                                on_change=State.set_and_validate_apellidos,
                                border_radius="md",
                                **input_style,
                            ),
                            rx.cond(
                                State.apellidos_valid,
                                rx.image(src="/check-green.svg", height="16px", ml="2"),
                                rx.box(),
                            ),
                        ),
                    ),
                    rx.vstack(
                        rx.text("Sexo", color=text_color),
                        rx.select(
                            ["Femenino", "Masculino", "Prefiero no decirlo"],
                            placeholder="Selecciona",
                            value=State.sexo,
                            on_change=State.set_sexo,
                            border_radius="md",
                            **input_style,
                        ),
                    ),
                    rx.vstack(
                        rx.text("Teléfono", color=text_color),
                        rx.hstack(
                            rx.input(
                                placeholder="Teléfono",
                                value=State.telefono,
                                on_change=State.set_and_validate_telefono,
                                border_radius="md",
                                **input_style,
                            ),
                            rx.cond(
                                State.telefono_valid,
                                rx.image(src="/check-green.svg", height="16px", ml="2"),
                                rx.box(),
                            ),
                        ),
                    ),
                    rx.vstack(
                        rx.text("Departamento", color=text_color),
                        rx.select(
                            [
                                "Amazonas",
                                "Antioquia",
                                "Arauca",
                                "Atlántico",
                                "Bolívar",
                                "Boyacá",
                                "Caldas",
                                "Caquetá",
                                "Casanare",
                                "Cauca",
                                "Cesar",
                                "Chocó",
                                "Córdoba",
                                "Cundinamarca",
                                "Guainía",
                                "Guaviare",
                                "Huila",
                                "La Guajira",
                                "Magdalena",
                                "Meta",
                                "Nariño",
                                "Norte de Santander",
                                "Putumayo",
                                "Quindío",
                                "Risaralda",
                                "Santander",
                                "Sucre",
                                "Tolima",
                                "Valle del Cauca",
                                "Vaupés",
                                "Vichada",
                                
                            ],
                            placeholder="Selecciona",
                            value=State.departamento,
                            on_change=State.set_and_validate_departamento,
                            border_radius="md",
                            **input_style,
                        ),
                    ),
                    rx.vstack(
                        rx.text("Ciudad", color=text_color),
                        rx.select(
                            State.ciudades_disponibles,
                            placeholder="Selecciona una ciudad",
                            value=State.ciudad,
                            on_change=State.set_and_validate_ciudad,
                            border_radius="md",
                            is_disabled=State.departamento == "",
                            **input_style,
                        ),
                    ),
                    rx.box(
                        rx.vstack(
                            label_requerido("Dirección"),
                            rx.input(
                                placeholder="Dirección",
                                value=State.direccion,
                                on_change=State.set_direccion,
                                border_radius="md",
                                **input_style,
                            ),
                        ),
                        grid_column="1 / -1",
                    ),
                    template_columns={"base": "1fr", "md": "repeat(3, 1fr)"},
                    gap="4",
                    width="100%",
                ),
                rx.grid(
                    rx.vstack(
                        rx.text("Etnia", color=text_color),
                        rx.select(
                            [
                                "Ninguna",
                                "Indígena",
                                "Afrocolombiano",
                                "Raizal",
                                "Palenquero",
                                "Gitano/a",
                                "Otro",
                            ],
                            placeholder="Selecciona",
                            value=State.etnia,
                            on_change=State.set_etnia,
                            border_radius="md",
                            **input_style,
                        ),
                    ),
                    rx.vstack(
                        rx.text("Características del ciudadano", color=text_color),
                        rx.select(
                            [
                                "Ninguna",
                                "Habitante de la calle",
                                "No brinda información",
                                "Peligro Inminente",
                                "Periodistas en ejercicio de su actividad",
                                "Primera Infancia",
                                "Veteranos Fuerza Pública",
                                "Víctimas - Conflicto Armado",
                            ],
                            placeholder="Selecciona una característica",
                            value=State.persona_vulnerable_registro,
                            on_change=State.set_persona_vulnerable_registro,
                            border_radius="md",
                            **input_style,
                        ),
                    ),
                    template_columns={"base": "1fr", "md": "repeat(2, 1fr)"},
                    gap="4",
                    width="100%",
                ),
                rx.vstack(
                    rx.checkbox(
                        "Acepto recibir notificaciones por correo",
                        is_checked=State.acepta_notificaciones,
                        on_change=State.set_acepta_notificaciones,
                        color=text_color,
                    ),
                    rx.checkbox(
                        rx.hstack(
                            rx.link(
                                "He leído y acepto la Política de Protección de Datos",
                                href="/politica-privacidad",
                                color="blue.500",
                            ),
                            rx.text("(Al aceptarla se mostrará un aviso)", color=rx.color_mode_cond(light="gray.500", dark="gray.400"), font_size="xs")
                        ),
                        is_checked=State.acepta_politica_datos,
                        on_change=State.preconfirmar_politica,
                        color=text_color,
                    ),
                    spacing="3",
                    padding_top="4",
                    align_items="start",
                    width="100%",
                ),
                rx.cond(
                    State.modal_politica_visible,
                    rx.box(
                        rx.box(
                            rx.heading("Confirmación de Política de Privacidad", size="4", color=rx.color_mode_cond(light="black", dark="white")),
                            rx.text(
                                "Al aceptar la Política de Protección de Datos, confirmas que has leído y comprendido el uso de tus datos personales.",
                                color=rx.color_mode_cond(light="gray.700", dark="gray.300"),
                                font_size="sm"
                            ),
                            rx.text(
                                "La aceptación es necesaria para continuar con el registro.",
                                color=rx.color_mode_cond(light="gray.600", dark="gray.400"),
                                font_size="sm"
                            ),
                            rx.hstack(
                                rx.button("Aceptar", on_click=State.confirmar_politica, color_scheme="blue"),
                                rx.button("Cancelar", on_click=State.cancelar_politica, variant="outline"),
                                spacing="3"
                            ),
                            spacing="4",
                            p="6",
                            bg=rx.color_mode_cond(light="white", dark="#1a202c"),
                            border_radius="2xl",
                            border="2px solid #2563eb",
                            box_shadow="0 20px 60px rgba(0, 0, 0, 0.3), 0 0 40px rgba(37, 99, 235, 0.2)",
                            width="100%",
                            max_width="520px"
                        ),
                        position="fixed",
                        inset="0",
                        bg="rgba(0,0,0,0.45)",
                        display="flex",
                        align_items="center",
                        justify_content="center",
                        z_index="1000",
                        p="6"
                    )
                ),
                rx.cond(
                    State.error_de_registro != "",
                    rx.text(State.error_de_registro, color="red.500", font_size="sm", font_weight="bold"),
                    rx.box(),
                ),
                rx.cond(
                    State.succes != "",
                    rx.text(State.succes, color="green.500", font_size="sm", font_weight="bold"),
                    rx.box(),
                ),
                rx.hstack(
                    rx.button(title, type="submit", color_scheme="blue", size="4", width={"base": "100%", "md": "220px"}),
                    rx.link(
                        "¿Ya tienes una cuenta? Inicia sesión",
                        href="/login",
                        margin_left={"base": "0", "md": "4"},
                        color="blue.500",
                        width={"base": "100%", "md": "auto"},
                    ),
                    spacing="4",
                    justify={"base": "center", "md": "start"},
                    width="100%",
                ),
                spacing="4",
                align_items="stretch",
                width="100%",
            ),
            on_submit=on_submit,
        ),
        p={"base": "4", "md": "8"},
        max_width={"base": "95%", "md": "1100px"},
        box_shadow="2xl",
        border_radius="2xl",
        bg=rx.color_mode_cond(light="white", dark="#1a202c"),
        width="100%",
    )


NAVY      = "#1e3a8a"
NAVY_DARK = "#172554"
ORANGE    = "#e85d04"
 
 
def navbar() -> rx.Component:
    # Estilo compartido para los links
    link_style = dict(
        color="rgba(255,255,255,0.88)",
        font_size="13px",
        font_weight="500",
        text_decoration="none",
        padding_x="10px",
        padding_y="6px",
        border_radius="7px",
        white_space="nowrap",
        transition="all 0.15s ease",
        _hover={
            "color": "white",
            "bg": "rgba(255,255,255,0.12)",
        },
    )
 
    # Link activo/destacado (Dashboard)
    link_active = {
        **link_style,
        "color": "white",
        "font_weight": "600",
        "bg": "rgba(255,255,255,0.10)",
    }
 
    return rx.box(
        rx.hstack(
            # ── Logo / marca izquierda ─────────────────────────────────
            rx.link(
                rx.hstack(
                    rx.box(
                        rx.icon("shield-check", size=16, color=ORANGE),
                        width="30px", height="30px",
                        border_radius="8px",
                        bg="rgba(232,93,4,0.18)",
                        display="flex",
                        align_items="center",
                        justify_content="center",
                        flex_shrink="0",
                    ),
                    rx.text(
                        "PQRS",
                        font_size="15px",
                        font_weight="800",
                        color="white",
                        letter_spacing="-0.01em",
                    ),
                    spacing="2",
                    align_items="center",
                ),
                href="/",
                text_decoration="none",
                flex_shrink="0",
            ),
 
            # ── Separador vertical ─────────────────────────────────────
            rx.box(
                width="1px", height="22px",
                bg="rgba(255,255,255,0.18)",
                flex_shrink="0",
            ),
 
            # ── Links de navegación ────────────────────────────────────
            rx.hstack(
                rx.link("Inicio", href="/", **link_style),
                rx.link("Nueva Solicitud", href="/solicitudes", **link_style),
                rx.link("Registro", href="/registro", **link_style),
                # Solo funcionarios
                rx.cond(
                    State.es_autentica & (State.rol_usuario == "funcionario"),
                    rx.hstack(
                        rx.link("Reportes", href="/reportes", **link_style),
                        rx.link("Registrar Funcionario", href="/registro-funcionario", **link_style),
                        rx.link("Ver Usuarios", href="/usuarios", **link_style),
                        rx.link("Cambiar Rol", href="/cambiar-rol", **link_style),
                        spacing="1",
                    ),
                    rx.box(),
                ),
                # Dashboard según rol
                rx.cond(
                    State.es_autentica,
                    rx.cond(
                        State.rol_usuario == "funcionario",
                        rx.link("Dashboard", href="/dashboard-funcionario", **link_active),
                        rx.link("Dashboard", href="/dashboard", **link_active),
                    ),
                    rx.box(),
                ),
                spacing="1",
                align_items="center",
                flex_wrap="wrap",
                overflow="hidden",
            ),
 
            rx.spacer(),
 
            # ── Controles derecha ──────────────────────────────────────
            rx.hstack(
                # Toggle modo oscuro
                rx.color_mode.button(
                    color="rgba(255,255,255,0.75)",
                    _hover={"color": "white"},
                ),
                # Avatar + email si está autenticado
                rx.cond(
                    State.es_autentica,
                    rx.hstack(
                        rx.box(
                            rx.icon("user", size=14, color="white"),
                            width="30px", height="30px",
                            border_radius="full",
                            bg="rgba(255,255,255,0.15)",
                            display="flex",
                            align_items="center",
                            justify_content="center",
                            flex_shrink="0",
                        ),
                        rx.text(
                            State.email_actual,
                            font_size="12px",
                            color="rgba(255,255,255,0.80)",
                            no_wrap=True,
                            overflow="hidden",
                            text_overflow="ellipsis",
                            max_width="160px",
                            display={"base": "none", "lg": "block"},
                        ),
                        spacing="2",
                        align_items="center",
                    ),
                    rx.box(),
                ),
                spacing="3",
                align_items="center",
                flex_shrink="0",
            ),
 
            width="100%",
            max_width="1400px",
            margin="0 auto",
            align_items="center",
            spacing="3",
            padding_x="20px",
        ),
 
        bg=f"linear-gradient(90deg, {NAVY_DARK} 0%, {NAVY} 100%)",
        border_bottom="1px solid rgba(255,255,255,0.08)",
        box_shadow="0 2px 8px rgba(0,0,0,0.18)",
        padding_y="10px",
        width="100%",
        position="sticky",
        top="0",
        z_index="100",
    )


# ── Paleta ───────────────────────────────────────────────────────────────────
NAVY       = "#1e3a8a"
NAVY_DARK  = "#172554"
NAVY_MID   = "#1d4ed8"
ORANGE     = "#ea580c"
ORANGE_L   = "#fed7aa"
TEAL       = "#0891b2"
GREEN      = "#15803d"
AMBER      = "#d97706"
RED_PQ     = "#dc2626"
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG    = _ldc("#f8fafc", "#060e1e")
TEXT_MAIN  = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB   = _ldc("#475569", "#7ea8c9")
CARD_BG    = _ldc("#ffffff", "#0d1f38")
CARD_BDR   = _ldc("#e2e8f0", "#1e3a5f")
SECT_BG    = _ldc("#f1f5f9", "#070d1a")
 
 
# ── Sub-componentes ───────────────────────────────────────────────────────────
 
def _utility_bar() -> rx.Component:
    return rx.box(
        rx.hstack(
            rx.text("GOV.CO", font_weight="800", color="white",
                    font_size="13px", letter_spacing="0.05em"),
            rx.spacer(),
            rx.hstack(
                rx.link("Opciones de Accesibilidad", href="#",
                        font_size="12px", color="rgba(255,255,255,0.7)",
                        text_decoration="none",
                        _hover={"color": "white"}),
                rx.text("|", color="rgba(255,255,255,0.3)", font_size="12px"),
                rx.link("Inicia sesión", href="/login",
                        font_size="12px", color="rgba(255,255,255,0.7)",
                        text_decoration="none", _hover={"color": "white"}),
                rx.text("|", color="rgba(255,255,255,0.3)", font_size="12px"),
                rx.link("Regístrate", href="/registro",
                        font_size="12px", color="rgba(255,255,255,0.7)",
                        text_decoration="none", _hover={"color": "white"}),
                spacing="3", align_items="center",
            ),
            width="100%", align_items="center",
            max_width="1280px", margin="0 auto",
            padding_x="24px",
        ),
        bg="#020617",
        border_bottom="1px solid rgba(255,255,255,0.06)",
        padding_y="8px",
        width="100%",
    )


def utility_bar() -> rx.Component:
    return _utility_bar()
 
 
def _hero() -> rx.Component:
    return rx.box(
        # Fondo con imagen + overlay gradiente
        rx.box(
            # Overlay gradiente oscuro sobre la imagen
            rx.box(
                position="absolute", inset="0",
                bg="linear-gradient(105deg, rgba(15,23,42,0.92) 0%, rgba(15,23,42,0.70) 55%, rgba(15,23,42,0.30) 100%)",
            ),
            # Contenido del hero
            rx.box(
                rx.container(
                    rx.hstack(
                        # Lado izquierdo — texto
                        rx.vstack(
                            # Chip etiqueta
                            rx.box(
                                rx.hstack(
                                    rx.box(width="8px", height="8px",
                                           border_radius="full", bg=ORANGE),
                                    rx.text("Plataforma oficial de atención ciudadana",
                                            font_size="12px", color="white",
                                            font_weight="600", letter_spacing="0.04em"),
                                    spacing="2", align_items="center",
                                ),
                                bg="rgba(234,88,12,0.18)",
                                border="1px solid rgba(234,88,12,0.35)",
                                border_radius="full",
                                padding_x="14px", padding_y="6px",
                                display="inline-flex",
                            ),
                            # Título principal
                            rx.heading(
                                "Atención PQRS",
                                rx.text("Enlace 1755", color=ORANGE,
                                        display="block", line_height="1"),
                                font_size={"base": "2.6rem", "md": "3.8rem"},
                                font_weight="900",
                                color="white",
                                line_height="1.05",
                                letter_spacing="-0.03em",
                                margin_top="8px",
                            ),
                            # Subtítulo
                            rx.text(
                                "Radica, consulta y gestiona tus Peticiones, Quejas, "
                                "Reclamos y Sugerencias de forma clara, rápida y segura.",
                                color="rgba(255,255,255,0.78)",
                                font_size={"base": "15px", "md": "17px"},
                                max_width="560px",
                                line_height="1.7",
                            ),
                            # Botones CTA
                            rx.hstack(
                                rx.link(
                                    rx.button(
                                        rx.hstack(
                                            rx.icon("file-plus", size=16),
                                            rx.text("Radicar PQRS", font_weight="700"),
                                            spacing="2",
                                        ),
                                        bg=ORANGE,
                                        color="white",
                                        border_radius="10px",
                                        height="48px",
                                        padding_x="24px",
                                        font_size="15px",
                                        _hover={"bg": "#c2410c", "transform": "translateY(-2px)"},
                                        box_shadow="0 4px 20px rgba(234,88,12,0.4)",
                                        transition="all 0.2s ease",
                                    ),
                                    href="/solicitudes",
                                ),
                                rx.link(
                                    rx.button(
                                        rx.hstack(
                                            rx.icon("search", size=16),
                                            rx.text("Consultar Estado", font_weight="600"),
                                            spacing="2",
                                        ),
                                        bg="rgba(255,255,255,0.10)",
                                        color="white",
                                        border="1.5px solid rgba(255,255,255,0.25)",
                                        border_radius="10px",
                                        height="48px",
                                        padding_x="24px",
                                        font_size="15px",
                                        _hover={
                                            "bg": "rgba(255,255,255,0.18)",
                                            "transform": "translateY(-2px)",
                                        },
                                        transition="all 0.2s ease",
                                    ),
                                    href="/consultar-estado",
                                ),
                                spacing="3", flex_wrap="wrap",
                            ),
                            spacing="5", align_items="start",
                            max_width="620px",
                        ),
                        # Tarjeta derecha eliminada — los accesos están en la sección inferior
                        spacing="8",
                        align_items="center",
                        justify="between",
                        flex_wrap="wrap",
                        width="100%",
                    ),
                    max_width="1280px",
                    padding_x={"base": "20px", "md": "40px"},
                    padding_y={"base": "64px", "md": "96px"},
                ),
                position="absolute", inset="0",
                display="flex", align_items="center",
            ),
            position="relative",
            height={"base": "520px", "md": "600px"},
            width="100%",
            style={
                "backgroundImage": "url('/Gemini_Generated_Image_ouyornouyornouyo.png')",
                "backgroundSize": "cover",
                "backgroundPosition": "center",
            },
        ),
        width="100%",
    )
 
 
def _stats_bar() -> rx.Component:
    def _stat(number: str, label: str) -> rx.Component:
        return rx.vstack(
            rx.text(number, font_size="2rem", font_weight="900",
                    color="white", line_height="1", letter_spacing="-0.03em"),
            rx.text(label, font_size="12px", color="rgba(255,255,255,0.6)",
                    font_weight="500"),
            spacing="1", align_items="center",
        )
 
    return rx.box(
        rx.container(
            rx.hstack(
                _stat("15", "días hábiles de respuesta"),
                rx.box(width="1px", height="40px", bg="rgba(255,255,255,0.15)"),
                _stat("4", "tipos de solicitud"),
                rx.box(width="1px", height="40px", bg="rgba(255,255,255,0.15)"),
                _stat("100%", "en línea"),
                rx.box(width="1px", height="40px", bg="rgba(255,255,255,0.15)"),
                _stat("Gratis", "sin costo para el ciudadano"),
                spacing="8",
                justify="center",
                align_items="center",
                flex_wrap="wrap",
                width="100%",
            ),
            max_width="900px",
            padding_x="24px",
        ),
        bg=f"linear-gradient(90deg, {NAVY_DARK} 0%, {NAVY} 100%)",
        padding_y="28px",
        width="100%",
    )
 
 
def _quick_action(icon: str, title: str, desc: str, cta: str,
                   href: str, color: str, bg: str) -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.box(
                rx.icon(icon, size=22, color=color),
                bg=bg,
                border_radius="12px",
                width="48px", height="48px",
                display="flex", align_items="center", justify_content="center",
                flex_shrink="0",
            ),
            rx.vstack(
                rx.text(title, font_size="15px", font_weight="700", color=TEXT_MAIN),
                rx.text(desc, font_size="12px", color=TEXT_SUB, line_height="1.6"),
                spacing="1", align_items="start",
            ),
            rx.spacer(),
            rx.link(
                rx.hstack(
                    rx.text(cta, font_size="13px", font_weight="600", color=color),
                    rx.icon("arrow-right", size=13, color=color),
                    spacing="1", align_items="center",
                ),
                href=href, text_decoration="none",
                _hover={"opacity": "0.8"},
            ),
            spacing="4", align_items="start",
            height="100%", width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_top=f"3px solid {color}",
        border_radius="16px",
        padding="22px",
        box_shadow=_ldc("0 1px 4px rgba(0,0,0,0.06)", "0 2px 16px rgba(0,0,0,0.3)"),
        transition="transform 0.2s ease, box-shadow 0.2s ease",
        _hover={
            "transform": "translateY(-4px)",
            "box_shadow": f"0 12px 32px {color}22",
        },
        width="100%",
        flex="1",
        min_width="200px",
    )
 
 
def _pqrs_badge(letter: str, title: str, desc: str,
                 color: str, bg: str) -> rx.Component:
    return rx.box(
        rx.hstack(
            rx.box(
                rx.text(letter, font_size="22px", font_weight="900",
                        color=color, line_height="1"),
                bg=bg,
                width="48px", height="48px",
                border_radius="12px",
                display="flex", align_items="center", justify_content="center",
                flex_shrink="0",
            ),
            rx.vstack(
                rx.text(title, font_size="14px", font_weight="700", color=TEXT_MAIN),
                rx.text(desc, font_size="12px", color=TEXT_SUB, line_height="1.5"),
                spacing="0", align_items="start",
            ),
            spacing="3", align_items="start", width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="18px",
        box_shadow=_ldc("0 1px 3px rgba(0,0,0,0.05)", "0 2px 12px rgba(0,0,0,0.25)"),
        width="100%",
        transition="transform 0.18s ease",
        _hover={"transform": "translateY(-2px)"},
    )
 
 
def _info_feature(icon: str, title: str, desc: str, color: str) -> rx.Component:
    return rx.hstack(
        rx.box(
            rx.icon(icon, size=18, color=color),
            bg=f"{color}15",
            border_radius="10px",
            width="40px", height="40px",
            display="flex", align_items="center", justify_content="center",
            flex_shrink="0",
        ),
        rx.vstack(
            rx.text(title, font_size="14px", font_weight="700", color=TEXT_MAIN),
            rx.text(desc, font_size="12px", color=TEXT_SUB, line_height="1.5"),
            spacing="0", align_items="start",
        ),
        spacing="3", align_items="start", width="100%",
    )
 
 
def _footer() -> rx.Component:
    link_style = dict(
        font_size="13px",
        color=TEXT_SUB,
        text_decoration="none",
        _hover={"color": TEXT_MAIN},
        transition="color 0.15s ease",
    )
    return rx.box(
        rx.container(
            rx.vstack(
                rx.hstack(
                    # Col 1
                    rx.vstack(
                        rx.hstack(
                            rx.box(
                                rx.icon("shield-check", size=16, color=ORANGE),
                                bg="rgba(234,88,12,0.15)",
                                border_radius="8px",
                                width="30px", height="30px",
                                display="flex", align_items="center", justify_content="center",
                            ),
                            rx.text("Sistema PQRS", font_size="15px",
                                    font_weight="800", color=TEXT_MAIN),
                            spacing="2", align_items="center",
                        ),
                        rx.text(
                            "Enlace 1755 — Plataforma oficial de atención ciudadana.",
                            font_size="12px", color=TEXT_SUB, line_height="1.6",
                            max_width="220px",
                        ),
                        spacing="3", align_items="start",
                    ),
                    # Col 2
                    rx.vstack(
                        rx.text("Servicios", font_size="12px", font_weight="700",
                                color=TEXT_MAIN, letter_spacing="0.06em",
                                text_transform="uppercase"),
                        rx.link("Radicar PQRS", href="/solicitudes", **link_style),
                        rx.link("Consultar estado", href="/consultar-estado", **link_style),
                        rx.link("Registro ciudadano", href="/registro", **link_style),
                        rx.link("Iniciar sesión", href="/login", **link_style),
                        spacing="2", align_items="start",
                    ),
                    # Col 3
                    rx.vstack(
                        rx.text("Legal", font_size="12px", font_weight="700",
                                color=TEXT_MAIN, letter_spacing="0.06em",
                                text_transform="uppercase"),
                        rx.link("Política de privacidad", href="/politica-privacidad", **link_style),
                        rx.link(
                            "Ley 1755 de 2015",
                            href="https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=65334",
                            target="_blank",
                            **link_style,
                        ),
                        rx.link("Habeas Data", href="#", **link_style),
                        spacing="2", align_items="start",
                    ),
                    # Col 4
                    rx.vstack(
                        rx.text("Contacto", font_size="12px", font_weight="700",
                                color=TEXT_MAIN, letter_spacing="0.06em",
                                text_transform="uppercase"),
                        rx.text("Calle 10 # 5-20, Buenaventura", font_size="12px", color=TEXT_SUB),
                        rx.text("PBX: (+57) 602 XXX XXXX", font_size="12px", color=TEXT_SUB),
                        rx.text("Lunes a Viernes, 7:30am–5:30pm", font_size="12px", color=TEXT_SUB),
                        spacing="2", align_items="start",
                    ),
                    spacing="8",
                    align_items="start",
                    justify="between",
                    flex_wrap="wrap",
                    width="100%",
                ),
                rx.divider(color=CARD_BDR),
                rx.hstack(
                    rx.text("© 2026 Sistema PQRS — Todos los derechos reservados.",
                            font_size="11px", color=TEXT_SUB),
                    rx.spacer(),
                    rx.hstack(
                        rx.image(src="/unival_logo.svg", height="28px",
                                 alt="Universidad del Valle"),
                        rx.image(src="/govco_logo.svg", height="28px",
                                 alt="GOV.CO"),
                        spacing="4",
                    ),
                    width="100%", align_items="center", flex_wrap="wrap", gap="3",
                ),
                spacing="6", width="100%",
            ),
            max_width="1280px",
            padding_x={"base": "20px", "md": "40px"},
            padding_y="48px",
        ),
        bg=_ldc("#f8fafc", "#060e1e"),
        border_top=f"1px solid {CARD_BDR}",
        width="100%",
    )
 
 
# ── Página principal ──────────────────────────────────────────────────────────
 
def index() -> rx.Component:
    hero_text = rx.color_mode_cond(light="rgba(15, 23, 42, 0.96)", dark="white")
    hero_sub = rx.color_mode_cond(light="rgba(15, 23, 42, 0.72)", dark="rgba(255,255,255,0.75)")
    card_bg = rx.color_mode_cond(light="white", dark="#111827")
    section_bg = rx.color_mode_cond(light="#f8fafc", dark="#020617")
    body_bg = rx.color_mode_cond(light="#f1f5f9", dark="#020617")

    return rx.box(
        rx.color_mode.button(position="top-right"),
        utility_bar(),
        navbar(),
        rx.box(
            rx.container(
                rx.hstack(
                    rx.vstack(
                        rx.text("Plataforma oficial de atención ciudadana", color="white", font_size="sm", bg="#2563eb", padding_x="3", padding_y="2", border_radius="full", mb="4"),
                        rx.heading("Atención PQRS - Enlace 1755", size="8", color="white", line_height="1.1"),
                        rx.text(
                            "Radica, consulta y gestiona tus Peticiones, Quejas, Reclamos y Sugerencias de forma clara, rápida y segura.",
                            color="rgba(255,255,255,0.85)",
                            font_size="lg",
                            max_width="680px"
                        ),
                        rx.hstack(
                            rx.link(rx.button("Radicar PQRS", color_scheme="blue", size="4", width="200px"), href="/solicitudes"),
                            rx.link(rx.button("Consultar Estado", color_scheme="blue", size="4", width="200px"), href="/consultar-estado"),
                            spacing="4",
                            flex_wrap="wrap"
                        ),
                        spacing="6",
                        align_items="start",
                        width="100%",
                        max_width="720px"
                    ),
                    rx.card(
                        rx.vstack(
                            rx.heading("Accesos rápidos", size="5", color="#000000"),
                            rx.link(rx.button("Registrarme", color_scheme="blue", width="100%"), href="/registro"),
                            rx.link(rx.button("Iniciar sesión", variant="solid", color_scheme="gray", width="100%"), href="/login"),
                            rx.link(rx.button("Nueva solicitud", variant="outline", color_scheme="gray", width="100%"), href="/solicitudes"),
                            rx.text("Disponible para ciudadanos que deseen registrar y hacer seguimiento a sus solicitudes.", color="dark", font_size="sm"),
                            spacing="4",
                            align_items="stretch"
                        ),
                        p="6",
                        bg="rgba(255,255,255,0.08)",
                        border="1px solid rgba(255,255,255,0.15)",
                        border_radius="2xl",
                        width="100%",
                        max_width="340px"
                    ),
                    spacing="8",
                    align_items="center",
                    justify="between",
                    flex_wrap="wrap"
                ),
                max_width="1200px",
                padding_y="20",
                padding_x="6"
            ),
            width="100%",
            min_height="520px",
            style={
                "backgroundImage": "linear-gradient(90deg, rgba(15,23,42,0.84), rgba(15,23,42,0.30)), url('/Gemini_Generated_Image_ouyornouyornouyo.png')",
                "backgroundSize": "cover",
                "backgroundPosition": "center",
                "backgroundRepeat": "no-repeat"
            }
        ),

        rx.container(
            rx.vstack(
                rx.vstack(
                    rx.heading("¿Qué deseas hacer hoy?", size="7", color="#0f172a"),
                    rx.text("Accede rápidamente a los servicios principales del sistema.", color="#475569", font_size="md"),
                    spacing="3",
                    align_items="center"
                ),
                rx.hstack(
                    quick_action_card("Radicar PQRS", "Crea una nueva petición, queja, reclamo o sugerencia.", "Ir al formulario", "/solicitudes", "blue"),
                    quick_action_card("Consultar estado", "Revisa el avance y respuesta de tus solicitudes.", "Consultar", "/consultar-estado", "cyan"),
                    quick_action_card("Registro ciudadano", "Crea tu cuenta para gestionar trámites de forma segura.", "Registrarme", "/registro", "green"),
                    quick_action_card("Iniciar sesión", "Accede a tu cuenta y continúa tus gestiones.", "Entrar", "/login", "gray"),
                    spacing="5",
                    justify="center",
                    flex_wrap="wrap"
                ),
                spacing="9",
                align_items="center"
            ),
            max_width="1200px",
            padding_y="20",
            padding_x="6"
        ),

        rx.box(
            rx.container(
                rx.vstack(
                    rx.heading("Atención clara y transparente para la ciudadanía", size="7", color="#0f172a"),
                    rx.text("Este portal facilita la recepción, gestión y seguimiento de solicitudes ciudadanas de manera organizada y accesible.", color="#64748b", font_size="md", text_align="center", max_width="850px"),
                    spacing="4",
                    align_items="center"
                ),
                rx.hstack(
                    info_card("Canal seguro", "Tus datos y solicitudes se gestionan en un entorno controlado."),
                    info_card("Trazabilidad", "Cada solicitud puede registrarse y consultarse con mayor claridad."),
                    info_card("Atención oportuna", "El sistema está pensado para mejorar tiempos y experiencia ciudadana."),
                    spacing="5",
                    justify="center",
                    flex_wrap="wrap"
                ),
                spacing="9",
                align_items="center"
            ),
            width="100%",
            bg=section_bg,
            padding_y="20"
        ),

        rx.container(
            rx.vstack(
                rx.heading("¿Qué significa PQRS?", size="7", color="#0f172a"),
                rx.hstack(
                    pqrs_badge("Petición", "Solicitud respetuosa de información o actuación por parte de la entidad.", "#2563eb"),
                    pqrs_badge("Queja", "Manifestación de inconformidad por la conducta o atención recibida.", "#f59e0b"),
                    pqrs_badge("Reclamo", "Expresión de inconformidad por una prestación deficiente o incumplimiento.", "#ef4444"),
                    pqrs_badge("Sugerencia", "Propuesta o recomendación para mejorar la atención o el servicio.", "#10b981"),
                    spacing="5",
                    justify="center",
                    flex_wrap="wrap"
                ),
                spacing="8",
                align_items="center"
            ),
            max_width="1200px",
            padding_y="20",
            padding_x="6"
        ),

        footer(),
        brand_footer(),
        bg=body_bg,
        width="100%",
        min_height="100vh"
    )


def quick_action_card(title: str, desc: str, button_text: str, href: str, accent: str = "blue") -> rx.Component:
    card_bg = rx.color_mode_cond(light="white", dark="#111827")
    border = rx.color_mode_cond(light="1px solid #e2e8f0", dark="1px solid #334155")
    text_main = rx.color_mode_cond(light="#0f172a", dark="white")
    text_sec = rx.color_mode_cond(light="#475569", dark="#cbd5e1")

    return rx.card(
        rx.vstack(
            rx.heading(title, size="5", color=text_main),
            rx.text(desc, color=text_sec, font_size="sm"),
            rx.link(rx.button(button_text, color_scheme=accent, width="100%"), href=href),
            spacing="4",
            align_items="start",
            width="100%"
        ),
        bg=card_bg,
        border=border,
        border_radius="2xl",
        p="6",
        width="100%",
        max_width="260px",
        box_shadow="lg"
    )


def info_card(title: str, desc: str) -> rx.Component:
    card_bg = rx.color_mode_cond(light="white", dark="#111827")
    border = rx.color_mode_cond(light="1px solid #e2e8f0", dark="1px solid #334155")
    text_main = rx.color_mode_cond(light="#0f172a", dark="white")
    text_sec = rx.color_mode_cond(light="#475569", dark="#cbd5e1")

    return rx.card(
        rx.vstack(
            rx.text(title, font_weight="bold", color=text_main, font_size="md"),
            rx.text(desc, color=text_sec, font_size="sm"),
            spacing="3",
            align_items="start"
        ),
        bg=card_bg,
        border=border,
        border_radius="xl",
        p="5",
        width="100%",
        max_width="360px",
        box_shadow="sm"
    )


def pqrs_badge(title: str, desc: str, color: str) -> rx.Component:
    card_bg = rx.color_mode_cond(light="white", dark="#111827")
    border = rx.color_mode_cond(light="1px solid #e2e8f0", dark="1px solid #334155")
    text_sec = rx.color_mode_cond(light="#475569", dark="#cbd5e1")

    return rx.card(
        rx.vstack(
            rx.box(
                rx.text(title, color="white", font_weight="bold", font_size="sm"),
                bg=color,
                padding_x="3",
                padding_y="2",
                border_radius="full"
            ),
            rx.text(desc, color=text_sec, font_size="sm"),
            spacing="3",
            align_items="start"
        ),
        bg=card_bg,
        border=border,
        border_radius="xl",
        p="5",
        width="100%",
        max_width="360px",
        box_shadow="sm"
    )


def footer() -> rx.Component:
    header_color = rx.color_mode_cond(light="black", dark="white")
    text_color = rx.color_mode_cond(light="gray.700", dark="gray.400")
    link_color = rx.color_mode_cond(light="blue.600", dark="blue.300")
    bg_footer = rx.color_mode_cond(light="#f7fafc", dark="#111827")
    border_color = rx.color_mode_cond(light="1px solid #e2e8f0", dark="1px solid #2d3748")

    return rx.container(
        rx.hstack(
            # Columna 1: Información de la Entidad
            rx.vstack(
                rx.heading("Información de la Entidad", size="6", color=header_color),
                rx.text("Sede Principal: Calle 10 # 5-20, Buenaventura, Valle del Cauca", color=text_color),
                rx.text("Código Postal: 760001", color=text_color),
                rx.text("PBX: (+57) 602 XXX XXXX", color=text_color),
                rx.link(
                    "Correo institucional: atencionalciudadano@empresa.gov.co", 
                    href="mailto:atencionalciudadano@empresa.gov.co",
                    color=link_color
                ),
                rx.link(
                    "Ley 1755 de 2015", 
                    href="https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=65334", 
                    target="_blank",
                    color=link_color
                ),
                rx.text(
                    "Horario de atención presencial: Lunes a Viernes, 7:30 a.m. - 12:00 p.m. y 2:00 p.m. - 5:30 p.m.",
                    color=text_color
                ),
                align_items="start",
            ),
            # Columna 2: Servicio al Ciudadano
            rx.vstack(
                rx.heading("Servicio al Ciudadano", size="6", color=header_color),
                rx.link("Radicar solicitud PQRS (HU4)", href="/solicitudes", color=link_color),
                rx.link("Consultar estado de solicitud (HU11)", href="/consultar-estado", color=link_color),
                rx.link("Preguntas Frecuentes (FAQ)", href="/faq", color=link_color),
                rx.link("Tiempos de respuesta (Ley 1755 de 2015)", href="/tiempos-respuesta", color=link_color),
                rx.link("Notificaciones por aviso y judiciales", href="/notificaciones", color=link_color),
                rx.link("Política de privacidad y protección de datos", href="/politica-privacidad", color=link_color),
                rx.link("Manual de usuario (Enlace 1755)", href="/manual-1755", color=link_color),
                align_items="start",
            ),
            # Columna 3: Contacto Directo y Redes
            rx.vstack(
                rx.heading("Contacto Directo y Redes", size="6", color=header_color),
                rx.text("Recepción de correspondencia física: Lunes a viernes, 8:00 a.m. a 4:00 p.m.", color=text_color),
                rx.text("Línea gratuita nacional: 01 8000 91XXXX", color=text_color),
                rx.hstack(
                    rx.link("Facebook", href="https://facebook.com", target="_blank", color=link_color),
                    rx.link("X/Twitter", href="https://twitter.com", target="_blank", color=link_color),
                    rx.link("YouTube", href="https://youtube.com", target="_blank", color=link_color),
                    rx.link("LinkedIn", href="https://linkedin.com", target="_blank", color=link_color),
                    spacing="4"
                ),
                rx.text("Sistema gestionado por: Enlace 1755 (Versión 1.0)", font_size="sm", color=text_color),
                align_items="start",
            ),
            spacing="9",
            align_items="start"
        ),
        width="100%",
        padding_top="24px",
        padding_bottom="24px",
        bg=bg_footer,
        border_top=border_color,
        justify="center"
    )


def brand_footer() -> rx.Component:
    """Franja inferior con logos institucionales (Universidad del Valle y GOV.CO)."""
    return rx.container(
        rx.hstack(
            rx.image(src="/unival_logo.svg", alt="Universidad del Valle", height="48px"),
            rx.spacer(),
            rx.image(src="/govco_logo.svg", alt="Gobierno de Colombia", height="48px"),
            spacing="6",
            align_items="center",
            justify="center"
        ),
        width="100%",
        padding_top="12px",
        padding_bottom="12px",
        bg="white",
        _dark={"bg": "gray.900", "borderColor": "gray.700"},
        border_top="1px solid #e2e8f0"
    )
 
    

def registro_page() -> rx.Component:
    return rx.box(
        navbar(),
        _modal_politica(),

        rx.center(
            rx.box(
                rx.vstack(

                    # ── Encabezado institucional ──────────────────────────
                    rx.box(
                        rx.vstack(
                            rx.hstack(
                                rx.text(
                                    "Regístrate en el Sistema PQRS" ,
                                    font_size={"base": "1.6rem", "md": "2rem"},
                                    font_weight="800",
                                    color=BLUE_ACC,
                                    letter_spacing="-0.02em",
                                ),
                                rx.text(
                                    "" ,
                                    font_size={"base": "1.6rem", "md": "2rem"},
                                    font_weight="800",
                                    color=TEXT_MAIN,
                                    letter_spacing="-0.02em",
                                ),
                                spacing="0", flex_wrap="wrap",
                            ),
                            rx.text(
                                "Completa el formulario para crear tu cuenta de ciudadano.",
                                font_size="14px", color=TEXT_SUB,
                            ),
                            spacing="2", align_items="start",
                        ),
                        border_bottom=f"3px solid {BLUE_ACC}",
                        padding_bottom="16px",
                        margin_bottom="4px",
                        width="100%",
                    ),

                    # ── Mensajes de error / éxito globales ────────────────
                    rx.cond(
                        State.error_de_registro != "",
                        rx.hstack(
                            rx.icon("circle-x", size=16, color="#dc2626"),
                            rx.text(State.error_de_registro, font_size="13px", color="#dc2626", font_weight="500"),
                            spacing="2", align_items="center",
                            bg="#fef2f2", border="1px solid #fecaca",
                            border_radius="8px", padding="10px 14px", width="100%",
                        ),
                    ),
                    rx.cond(
                        State.succes != "",
                        rx.hstack(
                            rx.icon("circle-check", size=16, color="#16a34a"),
                            rx.text(State.succes, font_size="13px", color="#16a34a", font_weight="500"),
                            spacing="2", align_items="center",
                            bg="#f0fdf4", border="1px solid #bbf7d0",
                            border_radius="8px", padding="10px 14px", width="100%",
                        ),
                    ),

                    # ── Secciones ─────────────────────────────────────────
                    _seccion_cuenta(),
                    _seccion_identificacion(),
                    _seccion_ubicacion(),
                    _seccion_diversidad(),
                    _seccion_autorizaciones(),

                    # ── Botón enviar ──────────────────────────────────────
                    rx.vstack(
                        rx.button(
                            rx.hstack(
                                rx.icon("user-plus", size=16),
                                rx.text("Crear mi cuenta", font_size="15px", font_weight="600"),
                                spacing="2",
                            ),
                            on_click=State.signup,
                            width="100%",
                            height="48px",
                            bg=BLUE_ACC,
                            color="white",
                            border_radius="10px",
                            cursor="pointer",
                            _hover={"bg": "#c2410c"},
                            _active={"bg": "#9a3412"},
                            transition="background 0.15s ease",
                            is_disabled=~(State.acepta_politica_datos & State.acepta_notificaciones),
                        ),
                        rx.hstack(
                            rx.text("¿Ya tienes una cuenta?", font_size="13px", color=TEXT_SUB),
                            rx.link(
                                "Inicia sesión",
                                href="/login",
                                color=BLUE_ACC,
                                font_size="13px",
                                font_weight="600",
                                text_decoration="none",
                                _hover={"text_decoration": "underline"},
                            ),
                            spacing="2", justify="center", width="100%",
                        ),
                        spacing="3", align_items="stretch", width="100%",
                    ),

                    spacing="5",
                    align_items="stretch",
                    width="100%",
                ),
                width="100%",
                max_width="900px",
                padding={"base": "20px 16px", "md": "32px 40px"},
            ),
            width="100%",
        ),

        bg=PAGE_BG,
        min_height="100vh",
        width="100%",
    )


# ── Tokens de color ──────────────────────────────────────────────────────────
def _ldc_reg(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)

ORANGE        = "#e85d04"
ORANGE_LIGHT  = "#fff7ed"
ORANGE_BORDER = "#fdba74"
NAVY          = "#1e3a8a"
BLUE_ACC      = "#2563eb"

PAGE_BG    = _ldc_reg("#f8fafc", "#0b1120")
CARD_BG    = _ldc_reg("#ffffff", "#1e293b")
CARD_BDR   = _ldc_reg("#e2e8f0", "#334155")
TEXT_MAIN  = _ldc_reg("#1e293b", "#f1f5f9")
TEXT_SUB   = _ldc_reg("#64748b", "#94a3b8")
TEXT_LABEL = _ldc_reg("#374151", "#cbd5e1")
INPUT_BG   = _ldc_reg("#ffffff", "#0f172a")
INPUT_BDR  = _ldc_reg("#d1d5db", "#475569")
INPUT_FOC  = BLUE_ACC
SECT_BG    = _ldc_reg("#f0f7ff", "#0f172a")
DIVIDER    = _ldc_reg("#e2e8f0", "#334155")


def _label(texto: str, required: bool = False) -> rx.Component:
    """Label con asterisco naranja si es requerido."""
    return rx.hstack(
        rx.text(texto, font_size="13px", font_weight="600", color=TEXT_LABEL),
        rx.cond(
            required,
            rx.text("*", color=ORANGE, font_size="13px", font_weight="700"),
            rx.box(),
        ),
        spacing="1",
        align_items="center",
        margin_bottom="4px",
    )


def _input_style() -> dict:
    return dict(
        bg=INPUT_BG,
        border=f"1px solid {INPUT_BDR}",
        border_radius="8px",
        color=TEXT_MAIN,
        font_size="14px",
        height="42px",
        padding_x="12px",
        width="100%",
        _placeholder={"color": TEXT_SUB, "font_size": "13px"},
        _focus={
            "outline": "none",
            "border_color": INPUT_FOC,
            "box_shadow": f"0 0 0 3px rgba(37,99,235,0.12)",
        },
    )


def _select_style() -> dict:
    return dict(
        bg=INPUT_BG,
        border=f"1px solid {INPUT_BDR}",
        border_radius="8px",
        color=TEXT_MAIN,
        font_size="14px",
        _focus={"border_color": INPUT_FOC},
    )


def _input_s() -> dict:
    """Compatibilidad: alias de `_input_style` usado en el código."""
    return _input_style()


def _select_s() -> dict:
    """Compatibilidad: alias de `_select_style` usado en el código."""
    return _select_style()


def _field(label: str, component: rx.Component, required: bool = True) -> rx.Component:
    """Campo completo: label + input."""
    return rx.vstack(
        _label(label, required),
        component,
        spacing="0",
        align_items="start",
        width="100%",
    )


def _field_with_check(
    label: str,
    component: rx.Component,
    is_valid,
    required: bool = True,
) -> rx.Component:
    """Campo con ícono de validación verde a la derecha."""
    return rx.vstack(
        _label(label, required),
        rx.hstack(
            component,
            rx.cond(
                is_valid,
                rx.box(
                    rx.icon("circle-check", size=18, color="#16a34a"),
                    flex_shrink="0",
                ),
                rx.box(width="18px"),
            ),
            spacing="2",
            align_items="center",
            width="100%",
        ),
        spacing="0",
        align_items="start",
        width="100%",
    )


def _section_header(icon: str, title: str, subtitle: str = "") -> rx.Component:
    """Encabezado de sección con línea naranja inferior."""
    return rx.box(
        rx.hstack(
            rx.box(
                rx.icon(icon, size=16, color=ORANGE),
                width="32px", height="32px",
                border_radius="8px",
                bg=ORANGE_LIGHT,
                border=f"1px solid {ORANGE_BORDER}",
                display="flex", align_items="center", justify_content="center",
                flex_shrink="0",
            ),
            rx.vstack(
                rx.text(title, font_size="14px", font_weight="700", color=TEXT_MAIN),
                rx.cond(
                    subtitle != "",
                    rx.text(subtitle, font_size="12px", color=TEXT_SUB),
                    rx.box(),
                ),
                spacing="0", align_items="start",
            ),
            spacing="3", align_items="center",
        ),
        border_bottom=f"2px solid {ORANGE}",
        padding_bottom="10px",
        margin_bottom="16px",
        width="100%",
    )


def _section(icon: str, title: str, content: rx.Component, subtitle: str = "") -> rx.Component:
    """Sección con encabezado y contenido en tarjeta estilizada."""
    return rx.box(
        _section_header(icon, title, subtitle),
        rx.box(
            content,
            bg=CARD_BG,
            border=f"1px solid {CARD_BDR}",
            border_radius="14px",
            padding="18px 20px",
            width="100%",
        ),
        spacing="4",
        width="100%",
    )


def _seccion_cuenta() -> rx.Component:
    """Correo + contraseñas."""
    return rx.box(
        _section_header("lock", "Datos de acceso", "Correo y contraseña para ingresar al sistema"),
        rx.grid(
            rx.box(
                _label("Correo Electrónico", required=True),
                rx.hstack(
                    rx.input(
                        placeholder="tu buzón electrónico",
                        type="email",
                        value=State.correo,
                        on_change=State.set_and_validate_correo,
                        on_blur=State.validar_correo_accion,
                        flex="1",
                        **_input_style(),
                    ),
                    rx.cond(
                        State.correo_validado,
                        rx.box(
                            rx.icon("circle-check", size=18, color="#16a34a"),
                            flex_shrink="0",
                        ),
                        rx.box(width="18px"),
                    ),
                    spacing="2", align_items="center", width="100%",
                ),
                rx.cond(
                    State.correo_confirmacion_visible,
                    rx.text(
                        State.correo_confirmacion_mensaje,
                        color=rx.cond(State.correo_validado, "#16a34a", "#dc2626"),
                        font_size="12px",
                        margin_top="4px",
                    ),
                    rx.box(),
                ),
                grid_column="1 / -1",
            ),
            _field_with_check(
                "Confirmar Correo Electrónico",
                rx.input(
                    placeholder="Repite tu correo electrónico",
                    type="email",
                    value=State.confirmar_correo,
                    on_change=State.set_confirmar_correo,
                    on_blur=lambda: State.set_confirmar_correo_match(State.correo == State.confirmar_correo),
                    **_input_style(),
                ),
                State.confirmar_correo_match & (State.confirmar_correo != ""),
            ),
            rx.vstack(
                _label("Contraseña", required=True),
                rx.hstack(
                    rx.input(
                        placeholder="Contraseña",
                        type=rx.cond(State.show_password, "text", "password"),
                        value=State.contraseña,
                        on_change=State.set_contraseña,
                        flex="1",
                        **_input_style(),
                    ),
                    rx.button(
                        rx.cond(
                            State.show_password,
                            rx.icon("eye_off", size=16, color=TEXT_SUB),
                            rx.icon("eye", size=16, color=TEXT_SUB),
                        ),
                        on_click=State.toggle_show_password,
                        variant="ghost", size="1",
                        _hover={"bg": "transparent"},
                        flex_shrink="0",
                    ),
                    spacing="1", align_items="center", width="100%",
                ),
                spacing="0", align_items="start", width="100%",
            ),
            _field(
                "Confirmar Contraseña",
                rx.input(
                    placeholder="Confirmar Contraseña",
                    type=rx.cond(State.show_password, "text", "password"),
                    value=State.confirmar_contraseña,
                    on_change=State.set_confirmar_contraseña,
                    **_input_style(),
                ),
            ),
            template_columns={"base": "1fr", "md": "1fr 1fr"},
            gap="4",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="20px 22px",
        width="100%",
    )


def _seccion_identificacion() -> rx.Component:
    """Tipo ID + número + nombres + apellidos + sexo."""
    return rx.box(
        _section_header("id-card", "Información personal", "Datos de identificación del ciudadano"),
        rx.grid(
            _field(
                "Tipo de Identificación",
                rx.select(
                    ["Cédula", "Pasaporte", "Tarjeta de Identidad"],
                    placeholder="Seleccione...",
                    value=State.tipo_identificacion,
                    on_change=State.set_tipo_identificacion,
                    **_select_style(),
                ),
                required=False,
            ),
            _field_with_check(
                "Número de Identificación",
                rx.input(
                    placeholder="Cédula/NIT",
                    value=State.numero_identificacion,
                    on_change=State.set_and_validate_numero_identificacion,
                    **_input_style(),
                ),
                State.numero_identificacion_valid,
            ),
            _field_with_check(
                "Nombres",
                rx.input(
                    placeholder="Nombre o razón social",
                    value=State.nombres,
                    on_change=State.set_and_validate_nombres,
                    **_input_style(),
                ),
                State.nombres_valid,
            ),
            _field_with_check(
                "Apellidos",
                rx.input(
                    placeholder="Apellidos",
                    value=State.apellidos,
                    on_change=State.set_and_validate_apellidos,
                    **_input_style(),
                ),
                State.apellidos_valid,
            ),
            _field(
                "Género",
                rx.select(
                    ["Femenino", "Masculino", "Prefiero no decirlo"],
                    placeholder="Seleccione...",
                    value=State.sexo,
                    on_change=State.set_sexo,
                    **_select_style(),
                ),
                required=False,
            ),
            _field_with_check(
                "Número de Contacto",
                rx.input(
                    placeholder="un teléfono de contacto",
                    value=State.telefono,
                    on_change=State.set_and_validate_telefono,
                    **_input_style(),
                ),
                State.telefono_valid,
            ),
            template_columns={"base": "1fr", "md": "1fr 1fr 1fr"},
            gap="4",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="20px 22px",
        width="100%",
    )


def _seccion_ubicacion() -> rx.Component:
    """Dirección + departamento + ciudad."""
    return rx.box(
        _section_header("map-pin", "Ubicación", "Dirección y municipio de residencia"),
        rx.grid(
            rx.box(
                _label("Dirección", required=True),
                rx.input(
                    placeholder="tu dirección de residencia",
                    value=State.direccion,
                    on_change=State.set_direccion,
                    **_input_style(),
                ),
                grid_column="1 / -1",
            ),
            _field_with_check(
                "Departamento",
                rx.select(
                    [
                        "Amazonas","Antioquia","Arauca","Atlántico","Bogotá D.C.",
                        "Bolívar","Boyacá","Caldas","Caquetá","Casanare","Cauca",
                        "Cesar","Chocó","Córdoba","Cundinamarca","Guainía","Guaviare",
                        "Huila","La Guajira","Magdalena","Meta","Nariño",
                        "Norte de Santander","Putumayo","Quindío","Risaralda",
                        "San Andrés y Providencia","Santander","Sucre","Tolima",
                        "Valle del Cauca","Vaupés","Vichada",
                    ],
                    placeholder="Seleccione...",
                    value=State.departamento,
                    on_change=State.set_and_validate_departamento,
                    **_select_style(),
                ),
                State.departamento_valid,
                required=True,
            ),
            _field_with_check(
                "Ciudad",
                rx.select(
                    State.ciudades_disponibles,
                    placeholder="Seleccione...",
                    value=State.ciudad,
                    on_change=State.set_and_validate_ciudad,
                    is_disabled=State.departamento == "",
                    **_select_style(),
                ),
                State.ciudad_valid,
                required=True,
            ),
            template_columns={"base": "1fr", "md": "1fr 1fr"},
            gap="4",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="20px 22px",
        width="100%",
    )


def _seccion_diversidad() -> rx.Component:
    """Etnia + característica de ciudadano."""
    return rx.box(
        _section_header("heart-handshake", "Diversidad e inclusión", "Opcional — ayuda a mejorar la atención"),
        rx.grid(
            _field(
                "Etnia",
                rx.select(
                    ["Ninguna","Indígena","Afrocolombiano","Raizal","Palenquero","Gitano/a","Otro"],
                    placeholder="Seleccione...",
                    value=State.etnia,
                    on_change=State.set_etnia,
                    **_select_style(),
                ),
                required=False,
            ),
            _field(
                "Características del ciudadano",
                rx.select(
                    [
                        "Ninguna","Habitante de la calle","No brinda información",
                        "Peligro Inminente","Periodistas en ejercicio de su actividad",
                        "Primera Infancia","Veteranos Fuerza Pública",
                        "Víctimas - Conflicto Armado",
                    ],
                    placeholder="Seleccione...",
                    value=State.persona_vulnerable_registro,
                    on_change=State.set_persona_vulnerable_registro,
                    **_select_style(),
                ),
                required=False,
            ),
            template_columns={"base": "1fr", "md": "1fr 1fr"},
            gap="4",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="20px 22px",
        width="100%",
    )


def _seccion_autorizaciones() -> rx.Component:
    """Checkboxes de habeas data y notificaciones."""
    return rx.box(
        _section_header("shield-check", "Autorizaciones", "Política de datos y notificaciones"),
        rx.vstack(
            rx.hstack(
                rx.checkbox(
                    is_checked=State.acepta_notificaciones,
                    on_change=State.set_acepta_notificaciones,
                    color_scheme="orange",
                    size="2",
                ),
                rx.text(
                    "Autorizo de manera expresa que me notifiquen o comuniquen al correo "
                    "electrónico aquí suministrado la respuesta a escritos o solicitudes, "
                    "así como cualquier información relacionada con mis trámites.",
                    font_size="13px",
                    color=TEXT_SUB,
                    line_height="1.6",
                ),
                spacing="3",
                align_items="start",
                width="100%",
                padding="14px 16px",
                bg=SECT_BG,
                border_radius="10px",
                border=f"1px solid {_ldc_reg('#bfdbfe','#1e3a5f')}",
            ),
            rx.hstack(
                rx.checkbox(
                    is_checked=State.acepta_politica_datos,
                    on_change=State.preconfirmar_politica,
                    color_scheme="orange",
                    size="2",
                ),
                rx.hstack(
                    rx.text("He leído y acepto la ", font_size="13px", color=TEXT_SUB),
                    rx.link(
                        "Política de Protección de Datos",
                        href="/politica-privacidad",
                        color=ORANGE,
                        font_size="13px",
                        font_weight="600",
                        text_decoration="none",
                        _hover={"text_decoration": "underline"},
                    ),
                    spacing="0",
                    flex_wrap="wrap",
                ),
                spacing="3",
                align_items="center",
                width="100%",
                padding="14px 16px",
                bg=ORANGE_LIGHT,
                border_radius="10px",
                border=f"1px solid {ORANGE_BORDER}",
            ),
            spacing="3",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="20px 22px",
        width="100%",
    )


def _modal_politica() -> rx.Component:
    """Modal de confirmación de política de datos."""
    return rx.cond(
        State.modal_politica_visible,
        rx.box(
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.box(
                            rx.icon("shield-check", size=20, color=ORANGE),
                            bg=ORANGE_LIGHT,
                            border_radius="10px",
                            width="40px", height="40px",
                            display="flex", align_items="center", justify_content="center",
                        ),
                        rx.vstack(
                            rx.heading("Confirmación de Política", size="4", color=TEXT_MAIN),
                            rx.text("Política de Protección de Datos Personales", font_size="12px", color=TEXT_SUB),
                            spacing="0", align_items="start",
                        ),
                        spacing="3", align_items="center", width="100%",
                    ),
                    rx.divider(),
                    rx.text(
                        "Al aceptar confirmas que has leído y comprendido cómo se usarán "
                        "tus datos personales para gestionar solicitudes PQRS.",
                        font_size="13px", color=TEXT_SUB, line_height="1.6",
                    ),
                    rx.text(
                        "La aceptación es necesaria para continuar con el registro.",
                        font_size="13px", color=TEXT_MAIN, font_weight="600",
                    ),
                    rx.hstack(
                        rx.button(
                            "Cancelar",
                            on_click=State.cancelar_politica,
                            variant="outline", border_radius="8px", flex="1",
                        ),
                        rx.button(
                            "Aceptar y continuar",
                            on_click=State.confirmar_politica,
                            bg=ORANGE, color="white", border_radius="8px", flex="1",
                            _hover={"bg": "#c2410c"},
                        ),
                        spacing="3", width="100%",
                    ),
                    spacing="4", align_items="stretch", width="100%",
                ),
                bg=CARD_BG,
                border=f"2px solid {ORANGE_BORDER}",
                border_radius="18px",
                padding="28px",
                width="100%",
                max_width="480px",
                box_shadow="0 20px 60px rgba(0,0,0,0.2)",
            ),
            position="fixed", inset="0",
            bg="rgba(15,23,42,0.55)",
            display="flex", align_items="center", justify_content="center",
            z_index="1000", padding="24px",
        ),
    )


def registro_funcionario_page() -> rx.Component:
    """Página de registro de funcionario — solo para funcionarios autenticados."""
    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("shield-x", size=48, color="#ef4444"),
            rx.heading("Acceso Denegado", size="7", color="#ef4444"),
            rx.text("Solo funcionarios autenticados pueden registrar nuevos funcionarios.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )

    return rx.cond(
        State.es_autentica & (State.rol_usuario == "funcionario"),
        rx.box(
            navbar(),
            _modal_politica(),
            rx.center(
                rx.box(
                    rx.vstack(
                        rx.box(
                            rx.hstack(
                                rx.text("Registrar", font_size="2rem", font_weight="800", color=NAVY),
                                rx.text(" Nuevo Funcionario", font_size="2rem", font_weight="800", color=TEXT_MAIN),
                                spacing="0", flex_wrap="wrap",
                            ),
                            rx.text("Crea la cuenta institucional del nuevo funcionario.", font_size="14px", color=TEXT_SUB),
                            border_bottom=f"3px solid {NAVY}",
                            padding_bottom="16px",
                            margin_bottom="4px",
                            width="100%",
                        ),
                        rx.cond(
                            State.error_de_registro != "",
                            rx.hstack(
                                rx.icon("circle-x", size=16, color="#dc2626"),
                                rx.text(State.error_de_registro, font_size="13px", color="#dc2626"),
                                spacing="2", align_items="center",
                                bg="#fef2f2", border="1px solid #fecaca",
                                border_radius="8px", padding="10px 14px", width="100%",
                            ),
                        ),
                        rx.cond(
                            State.succes != "",
                            rx.hstack(
                                rx.icon("circle-check", size=16, color="#16a34a"),
                                rx.text(State.succes, font_size="13px", color="#16a34a"),
                                spacing="2", align_items="center",
                                bg="#f0fdf4", border="1px solid #bbf7d0",
                                border_radius="8px", padding="10px 14px", width="100%",
                            ),
                        ),
                        _seccion_cuenta(),
                        _seccion_identificacion(),
                        _seccion_ubicacion(),
                        _seccion_diversidad(),
                        _seccion_autorizaciones(),
                        rx.button(
                            rx.hstack(
                                rx.icon("user-check", size=16),
                                rx.text("Registrar Funcionario", font_size="15px", font_weight="600"),
                                spacing="2",
                            ),
                            on_click=State.signup_funcionario,
                            width="100%", height="48px",
                            bg=NAVY, color="white",
                            border_radius="10px",
                            _hover={"bg": "#172554"},
                            transition="background 0.15s ease",
                            is_disabled=~(State.acepta_politica_datos & State.acepta_notificaciones),
                        ),
                        spacing="5", align_items="stretch", width="100%",
                    ),
                    width="100%", max_width="900px",
                    padding={"base": "20px 16px", "md": "32px 40px"},
                ),
                width="100%",
            ),
            bg=PAGE_BG, min_height="100vh", width="100%",
        ),
        acceso_denegado,
    )


def change_password_page() -> rx.Component:
    return rx.container(
        navbar(),
        rx.center(
            rx.card(
                rx.vstack(
                    rx.heading("Cambiar Contraseña", size={"base": "5", "md": "7"}, color=rx.color_mode_cond(light="black", dark="white")),
                    rx.input(placeholder="Contraseña actual", type="password", value=State.current_password, on_change=State.set_current_password, width="100%"),
                    rx.input(placeholder="Nueva contraseña", type="password", value=State.new_password, on_change=State.set_new_password, width="100%"),
                    rx.input(placeholder="Confirmar nueva contraseña", type="password", value=State.confirm_new_password, on_change=State.set_confirm_new_password, width="100%"),
                    rx.button("Cambiar contraseña", on_click=State.change_password, color_scheme="blue", width="100%"),
                    rx.text(State.change_pw_message, color="green.500", font_size="sm")
                ),
                p={"base": "4", "md": "8"},
                max_width={"base": "90%", "md": "560px"},
                width="100%",
            ),
            size="3"
        ),
        bg=rx.color_mode_cond(light="#f8fafc", dark="#0f172a")
    )
"""
pages/login.py
Módulo de la página de inicio de sesión.
Importar en pqrs.py:
    from pages.login import login_page
"""
import reflex as rx


def login_page() -> rx.Component:
    """
    Página de inicio de sesión.
    Diseño: tarjeta centrada, fondo gris claro, inputs con borde sutil,
    botón azul sólido — fiel al screenshot proporcionado.
    """
    # ── Tokens de color (modo claro / oscuro) ──────────────────────────────
    page_bg      = rx.color_mode_cond(light="#f3f4f6",   dark="#0f172a")
    card_bg      = rx.color_mode_cond(light="#ffffff",   dark="#1e293b")
    card_border  = rx.color_mode_cond(light="#e5e7eb",   dark="#334155")
    label_color  = rx.color_mode_cond(light="#111827",   dark="#f1f5f9")
    input_bg     = rx.color_mode_cond(light="#ffffff",   dark="#0f172a")
    input_border = rx.color_mode_cond(light="#d1d5db",   dark="#475569")
    input_color  = rx.color_mode_cond(light="#111827",   dark="#f1f5f9")
    ph_color     = rx.color_mode_cond(light="#9ca3af",   dark="#64748b")
    link_color   = rx.color_mode_cond(light="#2563eb",   dark="#60a5fa")
    footer_color = rx.color_mode_cond(light="#6b7280",   dark="#94a3b8")
    error_bg     = rx.color_mode_cond(light="rgba(239,68,68,0.08)", dark="rgba(239,68,68,0.15)")

    # ── Estilo compartido para los inputs ──────────────────────────────────
    input_style = dict(
        bg=input_bg,
        border=f"1.5px solid {input_border}",
        border_radius="8px",
        color=input_color,
        font_size="15px",
        height="44px",
        padding_x="14px",
        width="100%",
        _placeholder={"color": ph_color},
        _focus={
            "outline": "none",
            "border_color": "#2563eb",
            "box_shadow": "0 0 0 3px rgba(37,99,235,0.15)",
        },
    )

    return rx.vstack(
        # ── Toast + provider de notificaciones ────────────────────────────
        rx.toast.provider(position="top-center", close_button=True, offset="20px"),

        # ── Tarjeta central ───────────────────────────────────────────────
        rx.center(
            rx.box(
                rx.vstack(

                    # Título
                    rx.heading(
                        "Iniciar sesión",
                        size="6",
                        color=label_color,
                        font_weight="700",
                        letter_spacing="-0.02em",
                        margin_bottom="8px",
                    ),

                    # ── Campo: correo ──────────────────────────────────────
                    rx.input(
                        placeholder="Correo electrónico",
                        type="email",
                        value=State.correo,
                        on_change=State.set_correo,
                        **input_style,
                    ),

                    # ── Campo: contraseña ──────────────────────────────────
                    rx.box(
                        rx.input(
                            placeholder="Contraseña",
                            type=rx.cond(State.show_password, "text", "password"),
                            value=State.contraseña,
                            on_change=State.set_contraseña,
                            **input_style,
                            padding_right="44px",   # espacio para el ícono
                        ),
                        # Botón ojo — posicionado dentro del input
                        rx.button(
                            rx.cond(
                                State.show_password,
                                rx.icon("eye_off", size=18, color="#9ca3af"),
                                rx.icon("eye",     size=18, color="#9ca3af"),
                            ),
                            on_click=State.toggle_show_password,
                            variant="ghost",
                            position="absolute",
                            right="10px",
                            top="50%",
                            transform="translateY(-50%)",
                            padding="0",
                            min_width="28px",
                            height="28px",
                            display="flex",
                            align_items="center",
                            justify_content="center",
                            _hover={"bg": "transparent"},
                        ),
                        position="relative",
                        width="100%",
                    ),

                    # ── Mensaje de error ───────────────────────────────────
                    rx.cond(
                        State.error_de_contraseña != "",
                        rx.box(
                            rx.text(
                                State.error_de_contraseña,
                                color="#dc2626",
                                font_size="13px",
                                font_weight="500",
                            ),
                            bg=error_bg,
                            border_radius="6px",
                            padding="8px 12px",
                            width="100%",
                        ),
                        rx.box(),
                    ),

                    # ── Mensaje de éxito (ej: "Has cerrado sesión") ────────
                    rx.cond(
                        State.succes2 != "",
                        rx.text(
                            State.succes2,
                            color="#16a34a",
                            font_size="13px",
                            font_weight="500",
                        ),
                        rx.box(),
                    ),

                    # ── Botón Entrar ───────────────────────────────────────
                    rx.button(
                        "Entrar",
                        on_click=State.login,
                        width="100%",
                        height="44px",
                        bg="#1d4ed8",
                        color="white",
                        font_size="15px",
                        font_weight="600",
                        border_radius="8px",
                        cursor="pointer",
                        _hover={"bg": "#1e40af"},
                        _active={"bg": "#1e3a8a"},
                        transition="background 0.15s ease",
                    ),

                    # ── Enlace registro ────────────────────────────────────
                    rx.hstack(
                        rx.text(
                            "¿No tienes cuenta? ",
                            color=footer_color,
                            font_size="13px",
                        ),
                        rx.link(
                            "Regístrate",
                            href="/registro",
                            color=link_color,
                            font_size="13px",
                            font_weight="500",
                            text_decoration="none",
                            _hover={"text_decoration": "underline"},
                        ),
                        spacing="0",
                        align_items="center",
                    ),

                    # ── Espaciado general del vstack ───────────────────────
                    spacing="4",
                    align_items="stretch",
                    width="100%",
                ),

                # ── Estilos de la tarjeta ──────────────────────────────────
                bg=card_bg,
                border=f"1px solid {card_border}",
                border_radius="16px",
                box_shadow="0 1px 4px rgba(0,0,0,0.08), 0 4px 16px rgba(0,0,0,0.06)",
                padding="32px 36px",
                width="100%",
                max_width="420px",
            ),
            width="100%",
            min_height="100vh",
            padding_x="16px",
        ),

        # ── Fondo de página ────────────────────────────────────────────────
        bg=page_bg,
        width="100%",
        min_height="100vh",
        spacing="0",
    )

NAVY      = "#1e3a8a"
NAVY_DARK = "#172554"
ORANGE    = "#e85d04"
BLUE_ACC  = "#2563eb"
GREEN_OK  = "#16a34a"
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG   = _ldc("#f1f5f9", "#070d1a")
CARD_BG   = _ldc("#ffffff", "#0f1e35")
CARD_BDR  = _ldc("#e2e8f0", "#1e3a5f")
TEXT_MAIN = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB  = _ldc("#64748b", "#7ea8c9")
DIVIDER   = _ldc("#e2e8f0", "#1e3a5f")
 
 
def _section_card(icon, title, color, bg, body):
    return rx.box(
        rx.hstack(
            rx.box(
                rx.icon(icon, size=18, color=color),
                bg=bg, border_radius="10px",
                width="38px", height="38px",
                display="flex", align_items="center", justify_content="center",
                flex_shrink="0",
            ),
            rx.text(title, font_size="15px", font_weight="700", color=TEXT_MAIN),
            spacing="3", align_items="center",
            border_bottom=f"1px solid {DIVIDER}",
            padding_bottom="12px", margin_bottom="12px", width="100%",
        ),
        body,
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_left=f"4px solid {color}",
        border_radius="14px",
        padding="18px 20px",
        box_shadow=_ldc("0 1px 4px rgba(0,0,0,0.05)", "0 2px 12px rgba(0,0,0,0.3)"),
        width="100%",
        transition="box-shadow 0.2s ease",
        _hover={"box_shadow": _ldc("0 4px 20px rgba(0,0,0,0.08)", "0 4px 24px rgba(0,0,0,0.45)")},
    )
 
 
def _bullet(text, color=BLUE_ACC):
    return rx.hstack(
        rx.box(width="6px", height="6px", border_radius="full",
               bg=color, flex_shrink="0", margin_top="6px"),
        rx.text(text, font_size="13px", color=TEXT_SUB, line_height="1.7"),
        spacing="3", align_items="start", width="100%",
    )
 
 
def politica_privacidad_page() -> rx.Component:
    return rx.box(
        navbar(),
        rx.center(
            rx.box(
                rx.vstack(
                    # Encabezado
                    rx.box(
                        rx.hstack(
                            rx.box(
                                rx.icon("shield-check", size=24, color="white"),
                                bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                                border_radius="14px", width="52px", height="52px",
                                display="flex", align_items="center", justify_content="center",
                                box_shadow=f"0 6px 20px {NAVY}44", flex_shrink="0",
                            ),
                            rx.vstack(
                                rx.heading("Política de Privacidad", size="6", color=TEXT_MAIN,
                                           font_weight="800", letter_spacing="-0.02em"),
                                rx.text("Protección de Datos Personales — Sistema PQRS",
                                        font_size="13px", color=TEXT_SUB),
                                spacing="0", align_items="start",
                            ),
                            spacing="4", align_items="center",
                        ),
                        border_bottom=f"3px solid {NAVY}",
                        padding_bottom="16px", width="100%",
                    ),
 
                    # Aviso introductorio
                    rx.box(
                        rx.hstack(
                            rx.icon("info", size=16, color=BLUE_ACC),
                            rx.text(
                                "En esta plataforma tratamos tus datos con responsabilidad, transparencia y "
                                "seguridad. Tu información personal se usa únicamente para gestionar "
                                "solicitudes PQRS y mejorar el servicio. Al enviar una solicitud aceptas "
                                "la Política de Tratamiento de Datos Personales y los términos de uso.",
                                font_size="13px", color=TEXT_SUB, line_height="1.7",
                            ),
                            spacing="3", align_items="start",
                        ),
                        bg=_ldc("#eff6ff","#0a1628"),
                        border=f"1px solid {_ldc('#bfdbfe','#1e3a5f')}",
                        border_radius="12px", padding="14px 16px", width="100%",
                    ),
 
                    # Sección: Datos recolectados
                    _section_card(
                        "database", "Datos recolectados",
                        BLUE_ACC, _ldc("#eff6ff","#0f2744"),
                        rx.vstack(
                            _bullet("Correo electrónico", BLUE_ACC),
                            _bullet("Número y tipo de identificación", BLUE_ACC),
                            _bullet("Nombres y apellidos", BLUE_ACC),
                            _bullet("Teléfono de contacto", BLUE_ACC),
                            _bullet("Departamento, ciudad y dirección de residencia", BLUE_ACC),
                            _bullet("Información sobre etnia o condición de vulnerabilidad (opcional)", BLUE_ACC),
                            spacing="1", width="100%",
                        ),
                    ),
 
                    # Sección: Finalidad
                    _section_card(
                        "target", "Finalidad del tratamiento",
                        ORANGE, _ldc("#fff7ed","#2d1e00"),
                        rx.vstack(
                            _bullet("Contactar al ciudadano para dar respuesta a su solicitud PQRS.", ORANGE),
                            _bullet("Radicar y gestionar la solicitud dentro del sistema.", ORANGE),
                            _bullet("Generar trazabilidad y seguimiento de la atención prestada.", ORANGE),
                            _bullet("Enviar notificaciones sobre el estado y respuesta de la solicitud.", ORANGE),
                            spacing="1", width="100%",
                        ),
                    ),
 
                    # Sección: Derechos
                    _section_card(
                        "user-check", "Derechos del titular",
                        GREEN_OK, _ldc("#f0fdf4","#002818"),
                        rx.vstack(
                            _bullet("Conocer, actualizar y rectificar sus datos personales.", GREEN_OK),
                            _bullet("Solicitar la supresión de sus datos cuando no sean necesarios.", GREEN_OK),
                            _bullet("Revocar la autorización otorgada para el tratamiento.", GREEN_OK),
                            _bullet("Presentar quejas ante la Superintendencia de Industria y Comercio.", GREEN_OK),
                            spacing="1", width="100%",
                        ),
                    ),
 
                    # Sección: Seguridad
                    _section_card(
                        "lock", "Seguridad y conservación",
                        "#8b5cf6", _ldc("#f5f3ff","#1e1240"),
                        rx.vstack(
                            _bullet("Los datos se almacenan con medidas técnicas y organizativas adecuadas.", "#8b5cf6"),
                            _bullet("No se comparten con terceros salvo obligación legal.", "#8b5cf6"),
                            _bullet("Se conservan mientras sean necesarios para la atención de la solicitud.", "#8b5cf6"),
                            spacing="1", width="100%",
                        ),
                    ),
 
                    # Pie: nota legal + volver
                    rx.vstack(
                        rx.text(
                            "Base legal: Ley 1581 de 2012 y Decreto 1377 de 2013 — "
                            "Protección de Datos Personales en Colombia.",
                            font_size="11px", color=TEXT_SUB, text_align="center",
                        ),
                        rx.link(
                            rx.hstack(
                                rx.icon("arrow-left", size=14, color=NAVY),
                                rx.text("Volver al inicio", font_size="13px",
                                        font_weight="600", color=NAVY),
                                spacing="1",
                            ),
                            href="/", text_decoration="none",
                            _hover={"opacity": "0.8"},
                        ),
                        spacing="3", align_items="center", width="100%", padding_top="4px",
                    ),
 
                    spacing="4", align_items="stretch", width="100%",
                ),
                width="100%", max_width="720px",
                padding={"base": "24px 16px", "md": "40px 24px"},
            ),
            width="100%",
        ),
        bg=PAGE_BG, min_height="100vh", width="100%",
    )

def dashboard() -> rx.Component:
    return rx.cond(
        State.es_autentica & (State.rol_usuario == "ciudadano"),
        rx.box(
            navbar(),
            rx.center(
                rx.vstack(
                    rx.heading(
                        "Panel de Ciudadano",
                        size="6",
                        color=rx.color_mode_cond(light="black", dark="white")
                    ),
                    rx.text(
                        "¡Bienvenido! Aquí podrás gestionar tus Peticiones, Quejas, Reclamos y Sugerencias.",
                        color=rx.color_mode_cond(light="gray.600", dark="gray.300"),
                        font_size="sm"
                    ),
                    rx.vstack(
                        rx.heading(
                            "Mis Solicitudes",
                            size="5",
                            color=rx.color_mode_cond(light="black", dark="white")
                        ),
                        rx.cond(
                            State.solicitudes,
                            rx.vstack(
                                rx.foreach(
                                    State.solicitudes,
                                    lambda solicitud: rx.box(
                                        rx.vstack(
                                            rx.hstack(
                                                rx.badge(
                                                    solicitud["tipo_solicitud"],
                                                    color_scheme=rx.cond(
                                                        solicitud["tipo_solicitud"] == "Petición", "blue",
                                                        rx.cond(solicitud["tipo_solicitud"] == "Queja", "orange",
                                                        rx.cond(solicitud["tipo_solicitud"] == "Reclamo", "red", "green"))
                                                    )
                                                ),
                                                rx.badge(
                                                    solicitud["estado"],
                                                    color_scheme=rx.cond(
                                                        solicitud["estado"] == "Radicada", "blue",
                                                        rx.cond(solicitud["estado"] == "Actualizada", "orange", "green")
                                                    )
                                                ),
                                                rx.spacer(),
                                                rx.text(
                                                    solicitud["fecha"],
                                                    font_size="xs",
                                                    color="gray.400"
                                                ),
                                            ),
                                            rx.text(
                                                solicitud["radicado"],
                                                font_size="xs",
                                                color="gray.400",
                                                font_family="monospace",
                                                style={"wordBreak": "break-all"}
                                            ),
                                            rx.text(
                                                solicitud["asunto"],
                                                font_weight="semibold",
                                                font_size="sm",
                                                color=rx.color_mode_cond(light="gray.800", dark="white")
                                            ),
                                            rx.text(
                                             solicitud["descripcion"],
                                             font_size="sm",
                                              color=rx.color_mode_cond(light="gray.600", dark="gray.300"),
                                              style={
                                              "display": "-webkit-box",
                                              "WebkitLineClamp": "3",
                                              "WebkitBoxOrient": "vertical",
                                              "overflow": "hidden",
                                              "wordBreak": "break-word",   # <-- corta palabras largas
                                              "overflowWrap": "anywhere",  # <-- maneja URLs y texto sin espacios
                                                }
                                            ),
                                            rx.cond(
                                                solicitud.get("documento_basename"),
                                                rx.hstack(
                                                    rx.icon("paperclip", size=13, color="blue.400"),
                                                    rx.link(
                                                        solicitud["documento_basename"],
                                                        href=solicitud.get("documento_href", "#"),
                                                        color="blue.500",
                                                        font_size="xs",
                                                        target="_blank"
                                                    ),
                                                    spacing="1",
                                                    align_items="center"
                                                ),
                                                rx.box()
                                            ),
                                            spacing="2",
                                            align_items="start",
                                            width="100%"
                                        ),
                                        p="4",
                                        border="1px solid",
                                        border_color=rx.color_mode_cond(light="#e2e8f0", dark="#2d3748"),
                                        border_radius="lg",
                                        bg=rx.color_mode_cond(light="white", dark="#1e293b"),
                                        width="100%",
                                        _hover={
                                            "box_shadow": "sm",
                                            "border_color": "#3b82f6"
                                        }
                                    )
                                ),
                                spacing="3",
                                width="100%"
                            ),
                            rx.box(
                                rx.vstack(
                                    rx.icon("inbox", size=32, color="gray.300"),
                                    rx.text(
                                        "No tienes solicitudes registradas aún.",
                                        color="gray.400",
                                        font_size="sm",
                                        text_align="center"
                                    ),
                                    rx.link(
                                        rx.button(
                                            "Crear primera solicitud",
                                            color_scheme="blue",
                                            size="2"
                                        ),
                                        href="/solicitudes"
                                    ),
                                    spacing="3",
                                    align_items="center",
                                ),
                                p="8",
                                width="100%",
                                text_align="center"
                            )
                        ),
                        spacing="4",
                        width="100%"
                    ),
                    rx.button(
                        "Cerrar Sesión",
                        on_click=State.logout,
                        color_scheme="red",
                        size="2",
                        variant="soft",
                        width="100%"
                    ),
                    spacing="5",
                    align_items="stretch",
                    width="100%",
                    max_width="680px",
                    padding_x="4",
                    padding_y="8",
                ),
                width="100%",
                size="3",
                align_items="start",
                padding_top="6"
            ),
            bg=rx.color_mode_cond(light="#f8fafc", dark="#0f172a"),
            width="100%",
            size="3"
        ),
        rx.container(
            navbar(),
            rx.center(
                rx.vstack(
                    rx.heading("Acceso Denegado", size="8", color="red.500"),
                    rx.text("Esta página es solo para ciudadanos.", color="gray.600"),
                    rx.link(rx.button("Ir al Login", color_scheme="blue"), href="/login"),
                    spacing="4",
                    align_items="center"
                ),
                size="3"
            )
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# DASHBOARD DE FUNCIONARIO - Sub-componentes y helpers
# ──────────────────────────────────────────────────────────────────────────────

# ── Paleta de tokens ────────────────────────────────────────────────────────
NAVY       = "#1e3a8a"
NAVY_DARK  = "#172554"
BLUE_ACC   = "#3b82f6"
BLUE_LIGHT = "#eff6ff"

# ── Helpers de color modo-claro/oscuro ──────────────────────────────────────
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)

PAGE_BG    = _ldc("#f1f5f9", "#0b1120")
CARD_BG    = _ldc("#ffffff", "#1e293b")
CARD_BDR   = _ldc("#e2e8f0", "#334155")
TEXT_MAIN  = _ldc("#0f172a", "#f1f5f9")
TEXT_SUB   = _ldc("#64748b", "#94a3b8")
TEXT_MUTED = _ldc("#94a3b8", "#475569")
INPUT_BG   = _ldc("#ffffff", "#0f172a")
INPUT_BDR  = _ldc("#e2e8f0", "#334155")
DIV_COLOR  = _ldc("#f1f5f9", "#1e293b")


def _kpi_card(
    label: str,
    value,
    icon_name: str,
    accent: str,
    bg_accent: str,
) -> rx.Component:
    """Tarjeta KPI con icono, valor grande y etiqueta."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.box(
                    rx.icon(icon_name, size=20, color=accent),
                    bg=bg_accent,
                    border_radius="10px",
                    width="40px",
                    height="40px",
                    display="flex",
                    align_items="center",
                    justify_content="center",
                    flex_shrink="0",
                ),
                rx.spacer(),
                spacing="0",
                width="100%",
            ),
            rx.vstack(
                rx.text(
                    value,
                    font_size="2.2rem",
                    font_weight="800",
                    color=TEXT_MAIN,
                    line_height="1",
                    letter_spacing="-0.03em",
                ),
                rx.text(label, font_size="13px", color=TEXT_SUB, font_weight="500"),
                spacing="1",
                align_items="start",
            ),
            spacing="4",
            align_items="start",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="16px",
        padding="20px 22px",
        box_shadow="0 1px 3px rgba(0,0,0,0.06), 0 4px 12px rgba(0,0,0,0.04)",
        width="100%",
        transition="box-shadow 0.2s ease, transform 0.2s ease",
        _hover={
            "box_shadow": "0 4px 20px rgba(59,130,246,0.12)",
            "transform": "translateY(-2px)",
        },
    )


def _user_row(usuario: dict) -> rx.Component:
    """Fila de usuario con avatar inicial, email y badge de rol."""
    # Access dictionary items using .get() for proper Reflex typing
    email_var = usuario.get("email", "")
    rol_var = usuario.get("rol", "ciudadano")
    
    return rx.hstack(
        # Avatar con ícono de usuario
        rx.box(
            rx.icon("user", size=16, color="white"),
            width="36px",
            height="36px",
            border_radius="full",
            bg=rx.cond(rol_var == "funcionario", "#3b82f6", "#64748b"),
            display="flex",
            align_items="center",
            justify_content="center",
            flex_shrink="0",
        ),
        rx.vstack(
            rx.text(
                email_var,
                font_size="13px",
                font_weight="600",
                color=TEXT_MAIN,
                no_wrap=True,
                overflow="hidden",
                text_overflow="ellipsis",
                max_width="220px",
            ),
            rx.badge(
                rol_var,
                color_scheme=rx.cond(rol_var == "funcionario", "blue", "gray"),
                variant="soft",
                font_size="11px",
            ),
            spacing="1",
            align_items="start",
        ),
        spacing="3",
        align_items="center",
        padding_y="10px",
        border_bottom=f"1px solid {DIV_COLOR}",
        width="100%",
    )


def _solicitud_card(solicitud: dict) -> rx.Component:
    """Tarjeta compacta de solicitud con semáforo de días."""
    radicado_var = solicitud.get("radicado", "")
    estado_var = solicitud.get("estado", "")
    tipo_var = solicitud.get("tipo_solicitud", "")
    asunto_var = solicitud.get("asunto", "")
    creado_por_var = solicitud.get("creado_por", "—")
    fecha_var = solicitud.get("fecha", "")
    id_var = solicitud.get("id", 0)
    area_var = solicitud.get("area_responsable", "")
    
    return rx.box(
        rx.vstack(
            # Cabecera: radicado + badges
            rx.hstack(
                rx.text(
                    radicado_var,
                    font_size="11px",
                    font_weight="700",
                    color=BLUE_ACC,
                    font_family="monospace",
                ),
                rx.spacer(),
                # Semáforo
                rx.hstack(
                    rx.box(
                        width="8px",
                        height="8px",
                        border_radius="full",
                        bg=solicitud.get("semaforo_fill", "gray"),
                    ),
                    rx.text(
                        f"{solicitud.get('semaforo_remaining', '-')}d",
                        font_size="11px",
                        color=TEXT_MUTED,
                    ),
                    spacing="1",
                    align_items="center",
                ),
                rx.badge(
                    estado_var,
                    color_scheme=rx.cond(
                        estado_var == "Radicada", "orange",
                        rx.cond(estado_var == "Actualizada", "blue", "green"),
                    ),
                    variant="soft",
                    font_size="11px",
                ),
                width="100%",
                align_items="center",
            ),
            # Tipo + asunto
            rx.hstack(
                rx.badge(
                    tipo_var,
                    color_scheme=rx.cond(
                        tipo_var == "Petición", "blue",
                        rx.cond(tipo_var == "Queja", "orange",
                        rx.cond(tipo_var == "Reclamo", "red", "green")),
                    ),
                    variant="outline",
                    font_size="11px",
                ),
                rx.text(
                    asunto_var,
                    font_size="13px",
                    font_weight="600",
                    color=TEXT_MAIN,
                    no_wrap=True,
                    overflow="hidden",
                    text_overflow="ellipsis",
                ),
                spacing="2",
                align_items="center",
                width="100%",
            ),
            # Meta: creador + fecha
            rx.hstack(
                rx.icon("user", size=12, color=TEXT_MUTED),
                rx.text(creado_por_var, font_size="11px", color=TEXT_MUTED),
                rx.spacer(),
                rx.text(fecha_var, font_size="11px", color=TEXT_MUTED),
                spacing="1",
                align_items="center",
                width="100%",
            ),
            # Botones acción
            rx.hstack(
                rx.button(
                    rx.hstack(rx.icon("pencil", size=12), rx.text("Actualizar", font_size="12px"), spacing="1"),
                    on_click=lambda _e, id=id_var, estado=estado_var: State.abrir_editor_estado(id, estado),
                    size="1",
                    variant="outline",
                    color_scheme="blue",
                    border_radius="8px",
                ),
                rx.button(
                    rx.hstack(rx.icon("building-2", size=12), rx.text("Área", font_size="12px"), spacing="1"),
                    on_click=lambda _e, id=id_var, area=area_var: State.abrir_asignar_area(id, area),
                    size="1",
                    variant="outline",
                    color_scheme="green",
                    border_radius="8px",
                ),
                spacing="2",
            ),
            spacing="3",
            align_items="start",
            width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="16px 18px",
        box_shadow="0 1px 3px rgba(0,0,0,0.05)",
        width="100%",
        transition="box-shadow 0.2s ease, border-color 0.2s ease",
        _hover={"border_color": BLUE_ACC, "box_shadow": "0 4px 16px rgba(59,130,246,0.10)"},
    )


def _modal_editor_estado() -> rx.Component:
    """Modal flotante para actualizar estado de solicitud."""
    return rx.cond(
        State.editar_estado_id,
        rx.box(
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.heading("Actualizar Estado", size="5", color=TEXT_MAIN),
                        rx.spacer(),
                        rx.button(
                            rx.icon("x", size=16),
                            on_click=State.cerrar_editor_estado,
                            variant="ghost", size="1",
                            _hover={"bg": _ldc("#f1f5f9", "#334155")},
                        ),
                        width="100%", align_items="center",
                    ),
                    rx.divider(),
                    rx.vstack(
                        rx.text("Nuevo estado", font_size="13px", font_weight="600", color=TEXT_SUB),
                        rx.select(
                            ["Radicada", "Actualizada", "Cerrada"],
                            value=State.nuevo_estado,
                            on_change=State.set_nuevo_estado,
                            bg=INPUT_BG,
                            border=f"1px solid {INPUT_BDR}",
                            border_radius="8px",
                        ),
                        spacing="2", width="100%",
                    ),
                    rx.vstack(
                        rx.text(
                            rx.cond(State.nuevo_estado == "Cerrada",
                                    "Respuesta (obligatoria al cerrar)",
                                    "Respuesta (opcional)"),
                            font_size="13px", font_weight="600", color=TEXT_SUB,
                        ),
                        rx.text_area(
                            placeholder="Escribe la respuesta...",
                            value=State.respuesta_solicitud,
                            on_change=State.set_respuesta_solicitud,
                            rows="4",
                            bg=INPUT_BG,
                            border=f"1px solid {INPUT_BDR}",
                            border_radius="8px",
                            width="100%",
                        ),
                        spacing="2", width="100%",
                    ),
                    rx.cond(
                        State.mensaje_actualizar_estado != "",
                        rx.text(
                            State.mensaje_actualizar_estado,
                            color=rx.cond(
                                State.mensaje_actualizar_estado.contains("correctamente"),
                                "#16a34a", "#dc2626",
                            ),
                            font_size="13px", font_weight="600",
                        ),
                    ),
                    rx.hstack(
                        rx.button(
                            "Cancelar",
                            on_click=State.cerrar_editor_estado,
                            variant="outline", border_radius="8px", flex="1",
                        ),
                        rx.button(
                            "Guardar cambios",
                            on_click=State.actualizar_estado_solicitud,
                            color_scheme="blue", border_radius="8px", flex="1",
                        ),
                        spacing="3", width="100%",
                    ),
                    spacing="5", align_items="stretch", width="100%",
                ),
                bg=CARD_BG,
                border=f"1px solid {CARD_BDR}",
                border_radius="20px",
                padding="28px",
                width="100%",
                max_width="520px",
                box_shadow="0 20px 60px rgba(0,0,0,0.18)",
            ),
            position="fixed", inset="0",
            bg="rgba(15,23,42,0.55)",
            display="flex", align_items="center", justify_content="center",
            z_index="1000", padding="24px",
        ),
    )


def _modal_asignar_area() -> rx.Component:
    """Modal flotante para asignar área."""
    return rx.cond(
        State.asignar_area_id,
        rx.box(
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.heading("Asignar Área", size="5", color=TEXT_MAIN),
                        rx.spacer(),
                        rx.button(
                            rx.icon("x", size=16),
                            on_click=State.cerrar_asignar_area,
                            variant="ghost", size="1",
                        ),
                        width="100%", align_items="center",
                    ),
                    rx.divider(),
                    rx.vstack(
                        rx.text("Área responsable", font_size="13px", font_weight="600", color=TEXT_SUB),
                        rx.select(
                            ["Secretaría", "Contabilidad", "Bienestar", "Tesorería", "Atención al Ciudadano", "Otros"],
                            value=State.asignar_area_seleccionada,
                            on_change=State.set_asignar_area_seleccionada,
                            bg=INPUT_BG, border=f"1px solid {INPUT_BDR}", border_radius="8px",
                        ),
                        spacing="2", width="100%",
                    ),
                    rx.cond(
                        State.asignar_area_seleccionada == "Otros",
                        rx.vstack(
                            rx.text("Especifica el área", font_size="13px", font_weight="600", color=TEXT_SUB),
                            rx.input(
                                placeholder="Nombre del área",
                                value=State.asignar_area_nombre,
                                on_change=State.set_asignar_area_nombre,
                                bg=INPUT_BG, border=f"1px solid {INPUT_BDR}", border_radius="8px",
                            ),
                            spacing="2", width="100%",
                        ),
                    ),
                    rx.vstack(
                        rx.text("Mensaje para el ciudadano", font_size="13px", font_weight="600", color=TEXT_SUB),
                        rx.text_area(
                            placeholder="Escribe el mensaje...",
                            value=State.asignar_area_mensaje,
                            on_change=State.set_asignar_area_mensaje,
                            rows="4",
                            bg=INPUT_BG, border=f"1px solid {INPUT_BDR}",
                            border_radius="8px", width="100%",
                        ),
                        spacing="2", width="100%",
                    ),
                    rx.cond(
                        State.mensaje_asignacion != "",
                        rx.text(
                            State.mensaje_asignacion,
                            color=rx.cond(State.mensaje_asignacion.contains("correctamente"), "#16a34a", "#dc2626"),
                            font_size="13px", font_weight="600",
                        ),
                    ),
                    rx.hstack(
                        rx.button("Cancelar", on_click=State.cerrar_asignar_area, variant="outline", border_radius="8px", flex="1"),
                        rx.button("Enviar y asignar", on_click=State.asignar_area_con_mensaje, color_scheme="green", border_radius="8px", flex="1"),
                        spacing="3", width="100%",
                    ),
                    spacing="5", align_items="stretch", width="100%",
                ),
                bg=CARD_BG, border=f"1px solid {CARD_BDR}",
                border_radius="20px", padding="28px",
                width="100%", max_width="520px",
                box_shadow="0 20px 60px rgba(0,0,0,0.18)",
            ),
            position="fixed", inset="0",
            bg="rgba(15,23,42,0.55)",
            display="flex", align_items="center", justify_content="center",
            z_index="1000", padding="24px",
        ),
    )


def funcionario_dashboard() -> rx.Component:
    """Dashboard mejorado para funcionarios."""

    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("shield-x", size=48, color="#ef4444"),
            rx.heading("Acceso Denegado", size="7", color="#ef4444"),
            rx.text("Solo funcionarios autenticados pueden ver esta página.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )

    contenido = rx.box(
        navbar(),
        # ── Wrapper interior con padding ──────────────────────────────────
        rx.box(
            rx.vstack(

                # ── 1. Encabezado de bienvenida ───────────────────────────
                rx.box(
                    rx.hstack(
                        rx.vstack(
                            rx.hstack(
                                rx.box(
                                    rx.icon("layout-dashboard", size=22, color="white"),
                                    bg=NAVY,
                                    border_radius="12px",
                                    width="44px", height="44px",
                                    display="flex", align_items="center", justify_content="center",
                                ),
                                rx.vstack(
                                    rx.heading(
                                        "Panel de Funcionario",
                                        size="6", color=TEXT_MAIN,
                                        font_weight="800", letter_spacing="-0.02em",
                                    ),
                                    rx.text(
                                        "Gestión de solicitudes PQRS",
                                        font_size="13px", color=TEXT_SUB,
                                    ),
                                    spacing="0", align_items="start",
                                ),
                                spacing="3", align_items="center",
                            ),
                            spacing="1",
                        ),
                        rx.spacer(),
                        rx.button(
                            rx.hstack(
                                rx.icon("log-out", size=15),
                                rx.text("Cerrar Sesión", font_size="13px"),
                                spacing="2",
                            ),
                            on_click=State.logout,
                            color_scheme="red", variant="soft",
                            border_radius="10px", size="2",
                        ),
                        width="100%", align_items="center",
                        flex_wrap="wrap", gap="3",
                    ),
                    padding="20px 24px",
                    bg=CARD_BG,
                    border_bottom=f"1px solid {CARD_BDR}",
                ),

                # ── 2. Cuerpo con padding ─────────────────────────────────
                rx.box(
                    rx.vstack(

                        # ── KPIs ─────────────────────────────────────────
                        rx.grid(
                            _kpi_card("Total de solicitudes", State.numero_solicitudes,
                                      "files", "#3b82f6", "#eff6ff"),
                            _kpi_card("Radicadas", State.numero_solicitudes_radicadas,
                                      "file-text", "#f59e0b", "#fffbeb"),
                            _kpi_card("Actualizadas", State.numero_solicitudes_actualizadas,
                                      "refresh-cw", "#10b981", "#ecfdf5"),
                            _kpi_card("Cerradas", State.numero_solicitudes_cerradas,
                                      "check-circle", "#8b5cf6", "#f5f3ff"),
                            columns="4",
                            gap="4",
                            width="100%",
                            style={"gridTemplateColumns": "repeat(auto-fit, minmax(180px, 1fr))"},
                        ),

                        # ── Fila: Usuarios + Filtros ──────────────────────
                        rx.hstack(

                            # Panel usuarios
                            rx.box(
                                rx.vstack(
                                    rx.hstack(
                                        rx.hstack(
                                            rx.icon("users", size=16, color=BLUE_ACC),
                                            rx.heading("Usuarios recientes", size="4", color=TEXT_MAIN, font_weight="700"),
                                            spacing="2", align_items="center",
                                        ),
                                        rx.spacer(),
                                        rx.badge(
                                            State.usuarios_registrados_count,
                                            color_scheme="blue", variant="soft",
                                            border_radius="full",
                                        ),
                                        width="100%", align_items="center",
                                    ),
                                    rx.divider(),
                                    rx.vstack(
                                        rx.foreach(State.usuarios_registrados[:5], _user_row),
                                        spacing="0", width="100%",
                                    ),
                                    rx.cond(
                                        State.usuarios_registrados_count > 5,
                                        rx.text(
                                            "Se muestran los 5 más recientes.",
                                            font_size="11px", color=TEXT_MUTED,
                                        ),
                                    ),
                                    rx.link(
                                        rx.hstack(
                                            rx.text("Ver todos los usuarios", font_size="13px", font_weight="600", color=BLUE_ACC),
                                            rx.icon("arrow-right", size=14, color=BLUE_ACC),
                                            spacing="1",
                                        ),
                                        href="/usuarios",
                                    ),
                                    spacing="4", align_items="start", width="100%",
                                ),
                                bg=CARD_BG,
                                border=f"1px solid {CARD_BDR}",
                                border_radius="16px",
                                padding="20px 22px",
                                box_shadow="0 1px 3px rgba(0,0,0,0.05)",
                                flex="1",
                                min_width="280px",
                            ),

                            # Panel filtros
                            rx.box(
                                rx.vstack(
                                    rx.hstack(
                                        rx.icon("sliders-horizontal", size=16, color=BLUE_ACC),
                                        rx.heading("Filtros de búsqueda", size="4", color=TEXT_MAIN, font_weight="700"),
                                        spacing="2", align_items="center",
                                    ),
                                    rx.divider(),
                                    # Barra búsqueda
                                    rx.box(
                                        rx.hstack(
                                            rx.icon("search", size=16, color=TEXT_MUTED),
                                            rx.input(
                                                placeholder="Radicado, asunto, descripción...",
                                                value=State.query_solicitud,
                                                on_change=State.set_query_solicitud,
                                                border="none",
                                                bg="transparent",
                                                color=TEXT_MAIN,
                                                flex="1",
                                                _focus={"outline": "none"},
                                                font_size="13px",
                                            ),
                                            rx.button(
                                                "Buscar",
                                                on_click=State.buscar_solicitudes,
                                                size="1",
                                                color_scheme="blue",
                                                border_radius="8px",
                                            ),
                                            spacing="2", align_items="center", width="100%",
                                        ),
                                        bg=_ldc("#f8fafc", "#0f172a"),
                                        border=f"1px solid {INPUT_BDR}",
                                        border_radius="10px",
                                        padding="8px 12px",
                                        width="100%",
                                    ),
                                    rx.grid(
                                        rx.vstack(
                                            rx.text("Estado", font_size="12px", font_weight="600", color=TEXT_SUB),
                                            rx.select(
                                                ["Todas", "Radicada", "Actualizada", "Cerrada"],
                                                value=State.filter_estado_solicitud,
                                                on_change=State.set_filter_estado_solicitud,
                                                bg=INPUT_BG,
                                                border=f"1px solid {INPUT_BDR}",
                                                border_radius="8px",
                                                font_size="13px",
                                            ),
                                            spacing="1", width="100%",
                                        ),
                                        rx.vstack(
                                            rx.text("Tipo", font_size="12px", font_weight="600", color=TEXT_SUB),
                                            rx.select(
                                                ["Todas", "Petición", "Queja", "Reclamo", "Sugerencia"],
                                                value=State.filter_tipo_solicitud,
                                                on_change=State.set_filter_tipo_solicitud,
                                                bg=INPUT_BG,
                                                border=f"1px solid {INPUT_BDR}",
                                                border_radius="8px",
                                                font_size="13px",
                                            ),
                                            spacing="1", width="100%",
                                        ),
                                        columns="2", gap="3", width="100%",
                                    ),
                                    spacing="4", align_items="start", width="100%",
                                ),
                                bg=CARD_BG,
                                border=f"1px solid {CARD_BDR}",
                                border_radius="16px",
                                padding="20px 22px",
                                box_shadow="0 1px 3px rgba(0,0,0,0.05)",
                                width="340px",
                                flex_shrink="0",
                            ),

                            spacing="4",
                            align_items="start",
                            width="100%",
                            flex_wrap="wrap",
                        ),

                        # ── Lista de solicitudes ──────────────────────────
                        rx.box(
                            rx.vstack(
                                rx.hstack(
                                    rx.hstack(
                                        rx.icon("inbox", size=16, color=BLUE_ACC),
                                        rx.heading("Solicitudes", size="4", color=TEXT_MAIN, font_weight="700"),
                                        spacing="2", align_items="center",
                                    ),
                                    rx.spacer(),
                                    rx.badge(
                                        State.numero_solicitudes,
                                        color_scheme="blue", variant="soft", border_radius="full",
                                    ),
                                    width="100%", align_items="center",
                                ),
                                rx.divider(),
                                rx.cond(
                                    State.solicitudes,
                                    rx.vstack(
                                        rx.foreach(State.solicitudes_filtradas, _solicitud_card),
                                        spacing="3", width="100%",
                                    ),
                                    rx.center(
                                        rx.vstack(
                                            rx.icon("inbox", size=40, color=TEXT_MUTED),
                                            rx.text(
                                                "No hay solicitudes que coincidan.",
                                                color=TEXT_MUTED, font_size="14px",
                                            ),
                                            spacing="3", align_items="center",
                                        ),
                                        padding_y="40px", width="100%",
                                    ),
                                ),
                                spacing="4", align_items="start", width="100%",
                            ),
                            bg=CARD_BG,
                            border=f"1px solid {CARD_BDR}",
                            border_radius="16px",
                            padding="20px 22px",
                            box_shadow="0 1px 3px rgba(0,0,0,0.05)",
                            width="100%",
                        ),

                        spacing="6",
                        align_items="stretch",
                        width="100%",
                        max_width="1280px",
                        margin="0 auto",
                    ),
                    padding="24px",
                    width="100%",
                ),

                spacing="0",
                width="100%",
            ),
        ),

        # ── Modales ────────────────────────────────────────────────────────
        _modal_editor_estado(),
        _modal_asignar_area(),

        bg=PAGE_BG,
        min_height="100vh",
        width="100%",
    )

    return rx.cond(
        State.es_autentica & (State.rol_usuario == "funcionario"),
        contenido,
        acceso_denegado,
    )




NAVY      = "#1e3a8a"
NAVY_DARK = "#172554"
BLUE_ACC  = "#2563eb"
ORANGE    = "#e85d04"
GREEN_OK  = "#16a34a"
RED_ERR   = "#dc2626"
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG    = _ldc("#f1f5f9", "#070d1a")
CARD_BG    = _ldc("#ffffff", "#0f1e35")
CARD_BDR   = _ldc("#e2e8f0", "#1e3a5f")
TEXT_MAIN  = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB   = _ldc("#64748b", "#7ea8c9")
TEXT_LABEL = _ldc("#374151", "#cbd5e1")
INPUT_BG   = _ldc("#ffffff", "#0a1628")
INPUT_BDR  = _ldc("#d1d5db", "#1e3a5f")
UPLOAD_BG  = _ldc("#f8fafc", "#0a1628")
UPLOAD_BDR = _ldc("#cbd5e1", "#1e3a5f")
SECT_LINE  = _ldc("#e2e8f0", "#1e3a5f")
 
 
def _label(texto: str, required: bool = True) -> rx.Component:
    return rx.hstack(
        rx.text(texto, font_size="13px", font_weight="600", color=TEXT_LABEL),
        rx.cond(required, rx.text("*", color=ORANGE, font_size="13px"), rx.box()),
        spacing="1", align_items="center", margin_bottom="4px",
    )
 
 
def _input_s() -> dict:
    return dict(
        bg=INPUT_BG,
        border=f"1.5px solid {INPUT_BDR}",
        border_radius="10px",
        color=TEXT_MAIN,
        font_size="14px",
        width="100%",
        _placeholder={"color": TEXT_SUB, "font_size": "13px"},
        _focus={
            "outline": "none",
            "border_color": BLUE_ACC,
            "box_shadow": "0 0 0 3px rgba(37,99,235,0.12)",
        },
    )
 
 
def _select_s() -> dict:
    return dict(
        bg=INPUT_BG,
        border=f"1.5px solid {INPUT_BDR}",
        border_radius="10px",
        color=TEXT_MAIN,
        font_size="14px",
        _focus={"border_color": BLUE_ACC},
    )
 
 
def _section(icon: str, title: str, children: rx.Component) -> rx.Component:
    return rx.box(
        rx.hstack(
            rx.box(
                rx.icon(icon, size=15, color=BLUE_ACC),
                bg=_ldc("#eff6ff", "#0f2744"),
                border_radius="8px",
                width="30px", height="30px",
                display="flex", align_items="center", justify_content="center",
                flex_shrink="0",
            ),
            rx.text(title, font_size="13px", font_weight="700", color=TEXT_MAIN),
            spacing="2", align_items="center",
            border_bottom=f"1px solid {SECT_LINE}",
            padding_bottom="10px",
            margin_bottom="14px",
            width="100%",
        ),
        children,
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="14px",
        padding="18px 20px",
        width="100%",
    )
 
 
def solicitudes_page() -> rx.Component:
    # navbar() ya está definida en este módulo, no requiere importar desde pqrs
 
    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("lock", size=48, color=RED_ERR),
            rx.heading("Acceso Denegado", size="7", color=RED_ERR),
            rx.text("Necesitas iniciar sesión para crear una solicitud.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )
 
    contenido = rx.box(
        navbar(),
        rx.center(
            rx.box(
                rx.vstack(
 
                    # ── Encabezado ────────────────────────────────────────
                    rx.vstack(
                        rx.hstack(
                            rx.box(
                                rx.icon("file-plus", size=22, color="white"),
                                bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                                border_radius="14px",
                                width="50px", height="50px",
                                display="flex", align_items="center", justify_content="center",
                                box_shadow=f"0 6px 20px {NAVY}44",
                                flex_shrink="0",
                            ),
                            rx.vstack(
                                rx.heading(
                                    "Nueva Solicitud PQRS",
                                    size="6", color=TEXT_MAIN,
                                    font_weight="800", letter_spacing="-0.02em",
                                ),
                                rx.text(
                                    "Completa el formulario para radicar tu Petición, Queja, Reclamo o Sugerencia.",
                                    font_size="13px", color=TEXT_SUB,
                                ),
                                spacing="0", align_items="start",
                            ),
                            spacing="3", align_items="center",
                        ),
                        border_bottom=f"2px solid {_ldc('#e2e8f0','#1e3a5f')}",
                        padding_bottom="16px",
                        margin_bottom="4px",
                        width="100%",
                    ),
 
                    # ── Sección 1: Tipo + Área ────────────────────────────
                    _section("tag", "Clasificación de la solicitud",
                        rx.grid(
                            rx.vstack(
                                _label("Tipo de Solicitud"),
                                rx.select(
                                    ["Petición", "Queja", "Reclamo", "Sugerencia"],
                                    placeholder="Selecciona el tipo",
                                    value=State.tipo_solicitud,
                                    on_change=State.set_tipo_solicitud,
                                    **_select_s(),
                                ),
                                spacing="0", align_items="start", width="100%",
                            ),
                            rx.vstack(
                                _label("Área Responsable"),
                                rx.select(
                                    ["Secretaría","Contabilidad","Bienestar","Tesorería","Atención al Ciudadano","Otros"],
                                    placeholder="Selecciona el área",
                                    value=State.area_responsable,
                                    on_change=State.set_area_responsable,
                                    **_select_s(),
                                ),
                                spacing="0", align_items="start", width="100%",
                            ),
                            template_columns={"base": "1fr", "md": "1fr 1fr"},
                            gap="4", width="100%",
                        ),
                    ),
 
                    # Campo "otro área"
                    rx.cond(
                        State.area_responsable == "Otros",
                        rx.box(
                            rx.vstack(
                                _label("Especifica el área"),
                                rx.input(
                                    placeholder="Nombre del área responsable",
                                    value=State.area_otro,
                                    on_change=State.set_area_otro,
                                    **_input_s(),
                                ),
                                spacing="0", align_items="start", width="100%",
                            ),
                            bg=CARD_BG, border=f"1px solid {CARD_BDR}",
                            border_radius="14px", padding="18px 20px", width="100%",
                        ),
                    ),
 
                    # ── Sección 2: Asunto + Descripción ──────────────────
                    _section("file-text", "Detalle de la solicitud",
                        rx.vstack(
                            rx.vstack(
                                _label("Asunto"),
                                rx.text_area(
                                    placeholder="Escribe el asunto de tu solicitud...",
                                    value=State.asunto,
                                    on_change=State.set_asunto,
                                    rows="3",
                                    resize="vertical",
                                    min_height="90px",
                                    **_input_s(),
                                ),
                                spacing="0", align_items="start", width="100%",
                            ),
                            rx.vstack(
                                _label("Descripción detallada"),
                                rx.text_area(
                                    placeholder="Escribe aquí todos los detalles de tu solicitud...",
                                    value=State.descripcion,
                                    on_change=State.set_descripcion,
                                    rows="5",
                                    max_length=1000,
                                    resize="vertical",
                                    min_height="130px",
                                    **_input_s(),
                                ),
                                rx.hstack(
                                    rx.spacer(),
                                    rx.text(
                                        State.descripcion_len,
                                        font_size="12px",
                                        color=rx.cond(State.descripcion_len > 900, ORANGE, TEXT_SUB),
                                        font_weight="500",
                                    ),
                                    rx.text(" / 1000 caracteres", font_size="12px", color=TEXT_SUB),
                                    spacing="0", width="100%",
                                ),
                                spacing="1", align_items="start", width="100%",
                            ),
                            spacing="4", width="100%",
                        ),
                    ),
 
                    # ── Sección 3: Adjuntos ───────────────────────────────
                    _section("paperclip", "Documento adjunto (opcional)",
                        rx.vstack(
                            rx.text(
                                "Puedes adjuntar hasta 3 archivos PDF, PNG o JPG (máx. 10 MB en total). "
                                "Si necesitas enviar más, comprimelos en un ZIP.",
                                font_size="12px", color=TEXT_SUB, line_height="1.6",
                            ),
 
                            # ── Zona de carga: widget JS autocontenido ──────
                            rx.script("""
window.__pqrsUpload = window.__pqrsUpload || (function(){
    function init(root){
        if(root.__pqrsInit) return;
        root.__pqrsInit = true;
 
        const MAX  = 10*1024*1024, MAX_N = 3;
        const OK   = ['pdf','png','jpg','jpeg'];
        let   list = [];
 
        const zone  = root.querySelector('[data-zone]');
        const inp   = root.querySelector('[data-inp]');
        const lbl   = root.querySelector('[data-lbl]');
        const meta  = root.querySelector('[data-meta]');
        const barW  = root.querySelector('[data-barw]');
        const bar   = root.querySelector('[data-bar]');
        const usedL = root.querySelector('[data-used]');
        const freeL = root.querySelector('[data-free]');
        const rows  = root.querySelector('[data-rows]');
        const errEl = root.querySelector('[data-err]');
 
        function fmt(b){ return (b/1048576).toFixed(2)+' MB'; }
        function ext(n){ return n.split('.').pop().toLowerCase(); }
        function total(){ return list.reduce((a,f)=>a+f.size,0); }
 
        function showErr(msg){
            errEl.textContent=msg; errEl.style.display='block';
            clearTimeout(errEl._t);
            errEl._t=setTimeout(()=>errEl.style.display='none',6000);
        }
 
        function render(){
            const used=total(), free=Math.max(0,MAX-used);
            const pct=Math.min(100,(used/MAX)*100);
 
            // barra
            barW.style.display = list.length?'block':'none';
            bar.style.width    = pct+'%';
            const col = pct>=95?'#ef4444':pct>=75?'#f59e0b':'#10b981';
            bar.style.background=col;
            usedL.textContent = fmt(used)+' usado';
            freeL.textContent = fmt(free)+' libres';
            freeL.style.color = col;
 
            // zona label
            if(list.length){
                lbl.textContent = list.map(f=>f.name).join(', ');
                lbl.style.color = '#f0f6ff';
                meta.textContent= list.length+' archivo(s)';
            } else {
                lbl.textContent = 'Arrastra y suelta archivos aquí o haz clic para explorar';
                lbl.style.color = '#94a3b8';
                meta.textContent= 'PDF, PNG, JPG · máx. 10 MB · hasta 3 archivos';
            }
 
            // filas
            rows.innerHTML='';
            list.forEach(function(f,i){
                const d=document.createElement('div');
                d.style.cssText='display:flex;align-items:center;gap:8px;'+
                    'padding:7px 0;border-bottom:1px solid #1e3a5f;';
                d.innerHTML=
                    '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"'+
                    ' stroke="#3b82f6" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16'+
                    'a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'+
                    '</svg>'+
                    '<span style="flex:1;font-size:12px;color:#f0f6ff;">'+
                        f.name+' <em style="color:#64748b;font-style:normal;">('+fmt(f.size)+')</em>'+
                    '</span>'+
                    '<button style="background:none;border:none;cursor:pointer;'+
                    'color:#ef4444;font-size:14px;padding:2px 6px;" data-i="'+i+'">✕</button>';
                rows.appendChild(d);
            });
            rows.querySelectorAll('[data-i]').forEach(function(btn){
                btn.onclick=function(){ list.splice(+btn.dataset.i,1); render(); };
            });
        }
 
        inp.addEventListener('change',function(){
            const inc=Array.from(this.files);
            errEl.style.display='none';
            for(const f of inc){
                if(!OK.includes(ext(f.name))){
                    showErr('❌ "'+f.name+'" no permitido. Solo PDF, PNG o JPG.');
                    this.value=''; return;
                }
                if(f.size>MAX){
                    showErr('❌ "'+f.name+'" pesa '+fmt(f.size)+'. Máx. por archivo: 10 MB.');
                    this.value=''; return;
                }
                if(list.some(function(e){return e.name===f.name&&e.size===f.size;})) continue;
                if(list.length>=MAX_N){
                    showErr('❌ Solo puedes adjuntar hasta '+MAX_N+' archivos.');
                    this.value=''; return;
                }
                if(total()+f.size>MAX){
                    showErr('❌ Agregar "'+f.name+'" superaría el límite. Libre: '+fmt(MAX-total()));
                    this.value=''; return;
                }
                list.push({name:f.name,size:f.size});
            }
            this.value='';
            render();
        });
 
        // drag & drop
        zone.addEventListener('dragover',function(e){
            e.preventDefault();
            zone.style.borderColor='#2563eb';
            zone.style.background='#0f2744';
        });
        zone.addEventListener('dragleave',function(){
            zone.style.borderColor='#334155';
            zone.style.background='#0a1628';
        });
        zone.addEventListener('drop',function(e){
            e.preventDefault();
            zone.style.borderColor='#334155';
            zone.style.background='#0a1628';
            // simular change con los archivos soltados
            const dt=new DataTransfer();
            Array.from(e.dataTransfer.files).forEach(function(f){ dt.items.add(f); });
            inp.files=dt.files;
            inp.dispatchEvent(new Event('change'));
        });
    }
 
    // observar DOM para inicializar cuando el widget aparezca
    const obs=new MutationObserver(function(){
        document.querySelectorAll('[data-pqrs-upload]').forEach(init);
    });
    obs.observe(document.body,{childList:true,subtree:true});
    document.querySelectorAll('[data-pqrs-upload]').forEach(init);
    return {init:init};
})();
"""),
                            rx.el.div(
                                # Zona de carga
                                rx.el.div(
                                    rx.el.div(
                                        rx.el.svg(
                                            rx.el.path(d="M16 16 L12 12 L8 16"),
                                            rx.el.path(d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"),
                                            width="22", height="22", viewBox="0 0 24 24",
                                            fill="none", stroke="#3b82f6",
                                            stroke_width="2", stroke_linecap="round",
                                            style={"flexShrink":"0"},
                                        ),
                                        rx.el.div(
                                            rx.el.div(
                                                "Arrastra y suelta archivos aquí o haz clic para explorar",
                                                data_lbl=True,
                                                style={"fontSize":"13px","color":"#94a3b8","fontWeight":"500"},
                                            ),
                                            rx.el.div(
                                                "PDF, PNG, JPG · máx. 10 MB · hasta 3 archivos",
                                                data_meta=True,
                                                style={"fontSize":"11px","color":"#64748b","marginTop":"3px"},
                                            ),
                                        ),
                                        style={"display":"flex","alignItems":"center","gap":"12px"},
                                    ),
                                    rx.el.input(
                                        data_inp=True,
                                        type="file",
                                        accept="application/pdf,image/png,image/jpeg",
                                        multiple=True,
                                        style={
                                            "position":"absolute","inset":"0",
                                            "width":"100%","height":"100%",
                                            "opacity":"0","cursor":"pointer",
                                        },
                                    ),
                                    data_zone=True,
                                    style={
                                        "position":"relative","border":"2px dashed #334155",
                                        "borderRadius":"12px","padding":"16px 20px",
                                        "background":"#0a1628","cursor":"pointer",
                                        "transition":"border-color .15s,background .15s",
                                        "width":"100%",
                                    },
                                    onmouseenter="this.style.borderColor='#2563eb';this.style.background='#0f2744'",
                                    onmouseleave="this.style.borderColor='#334155';this.style.background='#0a1628'",
                                ),
                                # Barra de almacenamiento
                                rx.el.div(
                                    rx.el.div(
                                        rx.el.span("0.00 MB usado", data_used=True,
                                                   style={"fontSize":"11px","color":"#94a3b8"}),
                                        rx.el.span("10.00 MB libres", data_free=True,
                                                   style={"fontSize":"11px","fontWeight":"700","color":"#10b981"}),
                                        style={"display":"flex","justifyContent":"space-between","marginBottom":"4px"},
                                    ),
                                    rx.el.div(
                                        rx.el.div(
                                            data_bar=True,
                                            style={
                                                "height":"100%","width":"0%","borderRadius":"6px",
                                                "background":"#10b981",
                                                "transition":"width .35s ease,background .35s ease",
                                            },
                                        ),
                                        style={
                                            "background":"#1e3a5f","borderRadius":"6px",
                                            "height":"7px","overflow":"hidden",
                                        },
                                    ),
                                    data_barw=True,
                                    style={"display":"none","marginTop":"10px"},
                                ),
                                # Lista de archivos
                                rx.el.div(data_rows=True, style={"marginTop":"6px"}),
                                # Error
                                rx.el.div(
                                    data_err=True,
                                    style={
                                        "display":"none","marginTop":"8px",
                                        "padding":"8px 14px",
                                        "background":"#2d0000","border":"1px solid #991b1b",
                                        "borderRadius":"8px","fontSize":"12px","color":"#ef4444",
                                    },
                                ),
                                data_pqrs_upload=True,
                                style={"width":"100%"},
                            ),
 
                            # Error desde State (validaciones servidor)
                            rx.cond(
                                State.archivo_error_mensaje != "",
                                rx.hstack(
                                    rx.icon("alert-circle", size=14, color=RED_ERR),
                                    rx.text(State.archivo_error_mensaje, font_size="12px", color=RED_ERR),
                                    spacing="2", align_items="center",
                                ),
                            ),
                            spacing="3", width="100%",
                        ),
                    ),
 
                    # ── Autorización ──────────────────────────────────────
                    rx.hstack(
                        rx.checkbox(
                            is_checked=State.acepta_politica_solicitud,
                            on_change=State.set_acepta_politica_solicitud,
                            color_scheme="blue",
                            size="2",
                        ),
                        rx.hstack(
                            rx.text("He leído y acepto la ", font_size="13px", color=TEXT_SUB),
                            rx.link(
                                "Política de Tratamiento de Datos Personales",
                                href="/politica-privacidad",
                                color=BLUE_ACC,
                                font_size="13px",
                                font_weight="600",
                                text_decoration="none",
                                _hover={"text_decoration": "underline"},
                            ),
                            spacing="0", flex_wrap="wrap",
                        ),
                        spacing="3", align_items="center",
                        bg=_ldc("#eff6ff","#0a1628"),
                        border=f"1px solid {_ldc('#bfdbfe','#1e3a5f')}",
                        border_radius="10px",
                        padding="12px 16px",
                        width="100%",
                    ),
 
                    # ── Botón enviar ──────────────────────────────────────
                    rx.button(
                        rx.hstack(
                            rx.icon("send", size=16),
                            rx.text("Enviar Solicitud", font_size="15px", font_weight="600"),
                            spacing="2",
                        ),
                        on_click=State.crear_solicitud,
                        width="100%",
                        height="48px",
                        bg=rx.cond(
                            State.acepta_politica_solicitud,
                            f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                            _ldc("#e2e8f0","#1e293b"),
                        ),
                        color=rx.cond(State.acepta_politica_solicitud, "white", TEXT_SUB),
                        border_radius="12px",
                        cursor=rx.cond(State.acepta_politica_solicitud, "pointer", "not-allowed"),
                        box_shadow=rx.cond(
                            State.acepta_politica_solicitud,
                            f"0 4px 16px {NAVY}44",
                            "none",
                        ),
                        _hover=rx.cond(
                            State.acepta_politica_solicitud,
                            {"opacity": "0.92", "transform": "translateY(-1px)"},
                            {},
                        ),
                        transition="all 0.15s ease",
                        is_disabled=~State.acepta_politica_solicitud,
                    ),

                    # ── Mensaje resultado ─────────────────────────────────
                    rx.cond(
                        State.solicitud_mensaje != "",
                        rx.hstack(
                            rx.icon(
                                rx.cond(State.solicitud_mensaje.contains("éxito"), "circle-check", "circle-x"),
                                size=16,
                                color=rx.cond(State.solicitud_mensaje.contains("éxito"), GREEN_OK, RED_ERR),
                            ),
                            rx.text(
                                State.solicitud_mensaje, font_size="13px", font_weight="500",
                                color=rx.cond(State.solicitud_mensaje.contains("éxito"), GREEN_OK, RED_ERR),
                            ),
                            spacing="2", align_items="center",
                            bg=rx.cond(State.solicitud_mensaje.contains("éxito"),
                                       _ldc("#f0fdf4","#002818"), _ldc("#fef2f2","#2d0000")),
                            border=rx.cond(State.solicitud_mensaje.contains("éxito"),
                                           "1px solid #bbf7d0", "1px solid #fecaca"),
                            border_radius="10px", padding="12px 16px", width="100%",
                        ),
                    ),
 
                    spacing="4",
                    align_items="stretch",
                    width="100%",
                ),
                width="100%",
                max_width="720px",
                padding={"base": "20px 16px", "md": "36px 40px"},
            ),
            width="100%",
        ),
        bg=PAGE_BG, min_height="100vh", width="100%",
    )
 
    return rx.cond(State.es_autentica, contenido, acceso_denegado)

NAVY      = "#1e3a8a"
NAVY_DARK = "#172554"
BLUE_ACC  = "#2563eb"
GREEN_OK  = "#16a34a"
ORANGE    = "#f59e0b"
RED_ERR   = "#ef4444"
VIOLET    = "#8b5cf6"
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG   = _ldc("#f1f5f9", "#070d1a")
CARD_BG   = _ldc("#ffffff", "#0f1e35")
CARD_BDR  = _ldc("#e2e8f0", "#1e3a5f")
TEXT_MAIN = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB  = _ldc("#64748b", "#7ea8c9")
INPUT_BG  = _ldc("#f8fafc", "#0a1628")
INPUT_BDR = _ldc("#d1d5db", "#1e3a5f")
DIVIDER   = _ldc("#e2e8f0", "#1e3a5f")
ROW_BG    = _ldc("#f8fafc", "#0a1628")
 
 
# ── helpers ──────────────────────────────────────────────────────────────────
 
def _detail_row(label: str, value) -> rx.Component:
    """Fila de detalle: etiqueta gris + valor principal."""
    return rx.hstack(
        rx.text(label, font_size="12px", font_weight="600",
                color=TEXT_SUB, min_width="160px", flex_shrink="0"),
        rx.text(value, font_size="13px", color=TEXT_MAIN, font_weight="500"),
        spacing="4", align_items="start",
        padding_y="10px",
        border_bottom=f"1px solid {DIVIDER}",
        width="100%",
    )
 
 
def _estado_badge(estado) -> rx.Component:
    return rx.badge(
        estado,
        color_scheme=rx.cond(
            estado == "Radicada", "blue",
            rx.cond(estado == "Actualizada", "orange",
            rx.cond(estado == "Cerrada", "green", "gray")),
        ),
        variant="soft",
        font_size="12px",
        font_weight="600",
        padding_x="10px",
        border_radius="6px",
    )
 
 
def _timeline_dot(color: str, label: str, active: bool) -> rx.Component:
    return rx.vstack(
        rx.box(
            rx.box(
                width="10px", height="10px",
                border_radius="full",
                bg=rx.cond(active, color, _ldc("#cbd5e1","#334155")),
            ),
            width="22px", height="22px",
            border_radius="full",
            border=f"2px solid {rx.cond(active, color, _ldc('#e2e8f0','#1e3a5f'))}",
            display="flex", align_items="center", justify_content="center",
            bg=rx.cond(active, f"{color}18", "transparent"),
        ),
        rx.text(label, font_size="10px", font_weight="600",
                color=rx.cond(active, color, TEXT_SUB),
                text_align="center"),
        spacing="1", align_items="center",
    )
 
 
# ── página ───────────────────────────────────────────────────────────────────
 
def consultar_estado_page() -> rx.Component:
    return rx.box(
        navbar(),
        rx.center(
            rx.box(
                rx.vstack(
 
                    # ── Encabezado ────────────────────────────────────────
                    rx.vstack(
                        rx.box(
                            rx.icon("search", size=22, color="white"),
                            bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                            border_radius="14px",
                            width="52px", height="52px",
                            display="flex", align_items="center", justify_content="center",
                            box_shadow=f"0 6px 20px {NAVY}44",
                            flex_shrink="0",
                        ),
                        rx.vstack(
                            rx.heading(
                                "Consultar Estado de Solicitud",
                                size="6", color=TEXT_MAIN,
                                font_weight="800", letter_spacing="-0.02em",
                                text_align="center",
                            ),
                            rx.text(
                                "Ingresa el número de radicado para conocer el estado actual de tu solicitud.",
                                font_size="13px", color=TEXT_SUB, text_align="center",
                                max_width="480px",
                            ),
                            spacing="1", align_items="center",
                        ),
                        spacing="4", align_items="center", width="100%",
                    ),
 
                    # ── Formulario de búsqueda ────────────────────────────
                    rx.box(
                        rx.vstack(
                            rx.text(
                                "Número de Radicado",
                                font_size="13px", font_weight="600", color=TEXT_MAIN,
                            ),
                            rx.hstack(
                                rx.box(
                                    rx.hstack(
                                        rx.icon("hash", size=15, color=TEXT_SUB),
                                        rx.input(
                                            placeholder="Ej: PQRS-2026-ABC12345",
                                            value=State.consulta_radicado,
                                            on_change=State.set_consulta_radicado,
                                            border="none",
                                            bg="transparent",
                                            color=TEXT_MAIN,
                                            font_size="14px",
                                            font_family="monospace",
                                            flex="1",
                                            _focus={"outline": "none"},
                                            _placeholder={"color": TEXT_SUB, "font_family": "monospace"},
                                        ),
                                        spacing="2", align_items="center", width="100%",
                                    ),
                                    bg=INPUT_BG,
                                    border=f"1.5px solid {INPUT_BDR}",
                                    border_radius="10px",
                                    padding="10px 14px",
                                    flex="1",
                                    _focus_within={
                                        "border_color": BLUE_ACC,
                                        "box_shadow": "0 0 0 3px rgba(37,99,235,0.12)",
                                    },
                                    transition="border-color 0.15s, box-shadow 0.15s",
                                ),
                                rx.button(
                                    rx.hstack(
                                        rx.icon("search", size=15),
                                        rx.text("Consultar", font_size="13px", font_weight="600"),
                                        spacing="2",
                                    ),
                                    on_click=State.consultar_estado_solicitud,
                                    height="44px",
                                    bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                                    color="white",
                                    border_radius="10px",
                                    padding_x="20px",
                                    box_shadow=f"0 4px 14px {NAVY}44",
                                    _hover={"opacity": "0.9", "transform": "translateY(-1px)"},
                                    transition="all 0.15s ease",
                                    flex_shrink="0",
                                ),
                                spacing="3", align_items="center", width="100%",
                            ),
                            # Mensaje de estado de búsqueda
                            rx.cond(
                                State.consulta_mensaje != "",
                                rx.hstack(
                                    rx.icon(
                                        rx.cond(
                                            State.consulta_mensaje.contains("encontrada") &
                                            ~State.consulta_mensaje.contains("No se"),
                                            "circle-check", "circle-x",
                                        ),
                                        size=14,
                                        color=rx.cond(
                                            State.consulta_mensaje.contains("encontrada") &
                                            ~State.consulta_mensaje.contains("No se"),
                                            GREEN_OK, RED_ERR,
                                        ),
                                    ),
                                    rx.text(
                                        State.consulta_mensaje,
                                        font_size="12px", font_weight="500",
                                        color=rx.cond(
                                            State.consulta_mensaje.contains("encontrada") &
                                            ~State.consulta_mensaje.contains("No se"),
                                            GREEN_OK, RED_ERR,
                                        ),
                                    ),
                                    spacing="2", align_items="center",
                                ),
                            ),
                            spacing="3", align_items="start", width="100%",
                        ),
                        bg=CARD_BG,
                        border=f"1px solid {CARD_BDR}",
                        border_radius="16px",
                        padding="22px 24px",
                        box_shadow=_ldc("0 1px 4px rgba(0,0,0,0.06)", "0 2px 16px rgba(0,0,0,0.35)"),
                        width="100%",
                    ),
 
                    # ── Resultado ─────────────────────────────────────────
                    rx.cond(
                        State.solicitud_consultada,
                        rx.box(
                            rx.vstack(
 
                                # Cabecera resultado
                                rx.hstack(
                                    rx.hstack(
                                        rx.box(
                                            rx.icon("file-text", size=16, color=BLUE_ACC),
                                            bg=_ldc("#eff6ff","#0f2744"),
                                            border_radius="8px",
                                            width="32px", height="32px",
                                            display="flex", align_items="center", justify_content="center",
                                        ),
                                        rx.vstack(
                                            rx.text(
                                                "Resultado de la consulta",
                                                font_size="14px", font_weight="700", color=TEXT_MAIN,
                                            ),
                                            rx.text(
                                                State.solicitud_consultada.get("radicado",""),
                                                font_size="11px", color=BLUE_ACC,
                                                font_family="monospace", font_weight="600",
                                            ),
                                            spacing="0", align_items="start",
                                        ),
                                        spacing="2", align_items="center",
                                    ),
                                    rx.spacer(),
                                    _estado_badge(State.solicitud_consultada.get("estado","")),
                                    width="100%", align_items="center",
                                ),
 
                                rx.divider(color=DIVIDER),
 
                                # Timeline de estados
                                rx.box(
                                    rx.hstack(
                                        _timeline_dot(BLUE_ACC, "Radicada",
                                            State.solicitud_consultada.get("estado","") != ""),
                                        rx.box(height="2px", flex="1",
                                               bg=rx.cond(
                                                   State.solicitud_consultada.get("estado","") == "Actualizada",
                                                   ORANGE,
                                                   rx.cond(
                                                       State.solicitud_consultada.get("estado","") == "Cerrada",
                                                       GREEN_OK, DIVIDER,
                                                   ),
                                               )),
                                        _timeline_dot(ORANGE, "Actualizada",
                                            (State.solicitud_consultada.get("estado","") == "Actualizada") |
                                            (State.solicitud_consultada.get("estado","") == "Cerrada")),
                                        rx.box(height="2px", flex="1",
                                               bg=rx.cond(
                                                   State.solicitud_consultada.get("estado","") == "Cerrada",
                                                   GREEN_OK, DIVIDER,
                                               )),
                                        _timeline_dot(GREEN_OK, "Cerrada",
                                            State.solicitud_consultada.get("estado","") == "Cerrada"),
                                        spacing="0", align_items="center", width="100%",
                                    ),
                                    padding_y="12px",
                                    width="100%",
                                ),
 
                                rx.divider(color=DIVIDER),
 
                                # Detalles en filas
                                rx.vstack(
                                    _detail_row("Tipo de solicitud",
                                        State.solicitud_consultada.get("tipo_solicitud","")),
                                    _detail_row("Fecha de creación",
                                        State.solicitud_consultada.get("fecha","")),
                                    _detail_row("Área responsable",
                                        State.solicitud_consultada.get("area_responsable","—")),
                                    _detail_row("Asunto",
                                        State.solicitud_consultada.get("asunto","")),
                                    spacing="0", width="100%",
                                ),
 
                                # Descripción
                                rx.cond(
                                    State.solicitud_consultada.get("descripcion"),
                                    rx.vstack(
                                        rx.text("Descripción", font_size="12px",
                                                font_weight="600", color=TEXT_SUB),
                                        rx.box(
                                            rx.text(
                                                State.solicitud_consultada.get("descripcion",""),
                                                font_size="13px", color=TEXT_MAIN, line_height="1.7",
                                            ),
                                            bg=ROW_BG,
                                            border=f"1px solid {DIVIDER}",
                                            border_radius="10px",
                                            padding="14px 16px",
                                            width="100%",
                                        ),
                                        spacing="2", align_items="start", width="100%",
                                        padding_top="4px",
                                    ),
                                ),
 
                                # Respuesta del funcionario
                                rx.cond(
                                    State.solicitud_consultada.get("respuesta"),
                                    rx.vstack(
                                        rx.hstack(
                                            rx.icon("message-circle", size=14, color=GREEN_OK),
                                            rx.text("Respuesta del funcionario", font_size="12px",
                                                    font_weight="600", color=GREEN_OK),
                                            spacing="2", align_items="center",
                                        ),
                                        rx.box(
                                            rx.text(
                                                State.solicitud_consultada.get("respuesta",""),
                                                font_size="13px", color=TEXT_MAIN, line_height="1.7",
                                            ),
                                            bg=_ldc("#f0fdf4","#002818"),
                                            border="1px solid #bbf7d0",
                                            border_left=f"4px solid {GREEN_OK}",
                                            border_radius="10px",
                                            padding="14px 16px",
                                            width="100%",
                                        ),
                                        spacing="2", align_items="start", width="100%",
                                        padding_top="4px",
                                    ),
                                ),
 
                                # Documentos adjuntos
                                rx.cond(
                                    State.solicitud_consultada.get("documento_adjuntos"),
                                    rx.vstack(
                                        rx.hstack(
                                            rx.icon("paperclip", size=14, color=BLUE_ACC),
                                            rx.text("Documentos adjuntos", font_size="12px",
                                                    font_weight="600", color=TEXT_SUB),
                                            spacing="2", align_items="center",
                                        ),
                                        rx.vstack(
                                            rx.foreach(
                                                State.solicitud_consultada_adjuntos,
                                                lambda doc: rx.hstack(
                                                    rx.icon("file", size=13, color=BLUE_ACC),
                                                    rx.link(
                                                        doc["basename"],
                                                        href=doc["href"],
                                                        color=BLUE_ACC,
                                                        font_size="13px",
                                                        font_weight="500",
                                                        target="_blank",
                                                        text_decoration="none",
                                                        _hover={"text_decoration": "underline"},
                                                    ),
                                                    spacing="2", align_items="center",
                                                    padding_y="6px",
                                                    border_bottom=f"1px solid {DIVIDER}",
                                                    width="100%",
                                                ),
                                            ),
                                            spacing="0", width="100%",
                                        ),
                                        spacing="2", align_items="start", width="100%",
                                        padding_top="4px",
                                    ),
                                ),
 
                                spacing="4", align_items="start", width="100%",
                            ),
                            bg=CARD_BG,
                            border=f"1px solid {CARD_BDR}",
                            border_radius="16px",
                            padding="22px 24px",
                            box_shadow=_ldc("0 1px 4px rgba(0,0,0,0.06)", "0 2px 16px rgba(0,0,0,0.35)"),
                            width="100%",
                        ),
                    ),
 
                    spacing="5", align_items="stretch", width="100%",
                ),
                width="100%",
                max_width="680px",
                padding={"base": "24px 16px", "md": "48px 24px"},
            ),
            width="100%", min_height="90vh",
        ),
        bg=PAGE_BG, min_height="100vh", width="100%",
    )


# ── Paleta ───────────────────────────────────────────────────────────────────
NAVY       = "#1e3a8a"
NAVY_DARK  = "#172554"
BLUE_ACC   = "#3b82f6"
TEAL       = "#0ea5e9"
ORANGE     = "#f59e0b"
GREEN      = "#10b981"
RED        = "#ef4444"
VIOLET     = "#8b5cf6"
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG   = _ldc("#f1f5f9", "#070d1a")
CARD_BG   = _ldc("#ffffff", "#0f1e35")
CARD_BDR  = _ldc("#e2e8f0", "#1e3a5f")
TEXT_MAIN = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB  = _ldc("#64748b", "#7ea8c9")
INPUT_BG  = _ldc("#f8fafc", "#0a1628")
INPUT_BDR = _ldc("#e2e8f0", "#1e3a5f")
SECT_LINE = _ldc("#e2e8f0", "#1e3a5f")
 
 
# ── Helpers ──────────────────────────────────────────────────────────────────
 
def _card(children, **props) -> rx.Component:
    padding = props.pop("padding", "22px 24px")
    return rx.box(
        children,
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_radius="16px",
        padding=padding,
        box_shadow=_ldc(
            "0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.04)",
            "0 2px 16px rgba(0,0,0,0.4)",
        ),
        **props,
    )
 
 
def _kpi(label: str, value, color: str, icon: str, bg: str) -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.box(
                    rx.icon(icon, size=18, color=color),
                    bg=bg,
                    border_radius="10px",
                    width="38px", height="38px",
                    display="flex", align_items="center", justify_content="center",
                    flex_shrink="0",
                ),
                rx.spacer(),
                spacing="0", width="100%",
            ),
            rx.vstack(
                rx.text(
                    value,
                    font_size="2rem", font_weight="800",
                    color=TEXT_MAIN, line_height="1",
                    letter_spacing="-0.03em",
                ),
                rx.text(label, font_size="12px", color=TEXT_SUB, font_weight="500"),
                spacing="1", align_items="start",
            ),
            spacing="3", align_items="start", width="100%",
        ),
        bg=CARD_BG,
        border=f"1px solid {CARD_BDR}",
        border_top=f"3px solid {color}",
        border_radius="14px",
        padding="18px 20px",
        box_shadow=_ldc(
            "0 1px 3px rgba(0,0,0,0.05)",
            "0 2px 12px rgba(0,0,0,0.3)",
        ),
        transition="transform 0.18s ease, box-shadow 0.18s ease",
        _hover={
            "transform": "translateY(-3px)",
            "box_shadow": f"0 8px 24px {color}28",
        },
        width="100%",
    )
 
 
def _chart_card(title: str, subtitle: str, icon: str, color: str, chart: rx.Component) -> rx.Component:
    return _card(
        rx.vstack(
            # Header
            rx.hstack(
                rx.hstack(
                    rx.box(
                        rx.icon(icon, size=15, color=color),
                        bg=f"{color}18",
                        border_radius="8px",
                        width="30px", height="30px",
                        display="flex", align_items="center", justify_content="center",
                    ),
                    rx.vstack(
                        rx.text(title, font_size="14px", font_weight="700", color=TEXT_MAIN),
                        rx.text(subtitle, font_size="11px", color=TEXT_SUB),
                        spacing="0", align_items="start",
                    ),
                    spacing="2", align_items="center",
                ),
                rx.spacer(),
                spacing="0", width="100%",
            ),
            rx.divider(color=SECT_LINE, margin_y="4px"),
            chart,
            spacing="3", align_items="start", width="100%",
        ),
        width="100%",
    )
 
 
def _area_row(row: dict) -> rx.Component:
    return rx.hstack(
        rx.box(
            width="8px", height="8px",
            border_radius="full",
            bg=BLUE_ACC, flex_shrink="0",
        ),
        rx.text(row.get("name", ""), font_size="13px", color=TEXT_MAIN, flex="1"),
        rx.box(
            rx.text(
                row.get("total", 0),
                font_size="13px", font_weight="700", color=BLUE_ACC,
            ),
            bg=_ldc("#eff6ff", "#0f2744"),
            border_radius="6px",
            padding_x="10px", padding_y="2px",
        ),
        spacing="3", align_items="center", width="100%",
        padding_y="8px",
        border_bottom=f"1px solid {SECT_LINE}",
    )
 
 
# ── Página ────────────────────────────────────────────────────────────────────
 
def reportes_page() -> rx.Component:
    # navbar is defined in this module
 
    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("shield-x", size=48, color=RED),
            rx.heading("Acceso Denegado", size="7", color=RED),
            rx.text("Solo funcionarios autenticados pueden ver reportes.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )
 
    contenido = rx.box(
        navbar(),
 
        rx.box(
            rx.vstack(
 
                # ── Encabezado ────────────────────────────────────────────
                rx.hstack(
                    rx.vstack(
                        rx.hstack(
                            rx.box(
                                rx.icon("bar-chart-2", size=20, color="white"),
                                bg=NAVY,
                                border_radius="12px",
                                width="44px", height="44px",
                                display="flex", align_items="center", justify_content="center",
                                flex_shrink="0",
                            ),
                            rx.vstack(
                                rx.heading(
                                    "Reportes PQRS",
                                    size="6", color=TEXT_MAIN,
                                    font_weight="800", letter_spacing="-0.02em",
                                ),
                                rx.text(
                                    "Panel de métricas, volumen y tiempos de respuesta",
                                    font_size="13px", color=TEXT_SUB,
                                ),
                                spacing="0", align_items="start",
                            ),
                            spacing="3", align_items="center",
                        ),
                        spacing="1",
                    ),
                    rx.spacer(),
                    # Botones de descarga
                    rx.hstack(
                        rx.button(
                            rx.hstack(
                                rx.icon("download", size=14),
                                rx.text("Excel", font_size="13px"),
                                spacing="2",
                            ),
                            on_click=State.descargar_excel_y_abrir,
                            bg=GREEN, color="white",
                            border_radius="9px", size="2",
                            _hover={"bg": "#059669"},
                        ),
                        rx.button(
                            rx.hstack(
                                rx.icon("download", size=14),
                                rx.text("CSV", font_size="13px"),
                                spacing="2",
                            ),
                            on_click=State.descargar_csv_y_abrir,
                            bg=TEAL, color="white",
                            border_radius="9px", size="2",
                            _hover={"bg": "#0284c7"},
                        ),
                        spacing="2",
                    ),
                    width="100%", align_items="center",
                    flex_wrap="wrap", gap="3",
                ),
 
                # ── Filtros ───────────────────────────────────────────────
                _card(
                    rx.hstack(
                        rx.hstack(
                            rx.icon("filter", size=14, color=TEXT_SUB),
                            rx.text("Filtros", font_size="13px", font_weight="600", color=TEXT_SUB),
                            spacing="2", align_items="center",
                        ),
                        rx.select(
                            ["Últimos 12 meses", "Últimos 6 meses", "Este año"],
                            placeholder="Rango de fecha",
                            bg=INPUT_BG,
                            border=f"1px solid {INPUT_BDR}",
                            border_radius="8px",
                            font_size="13px",
                            color=TEXT_MAIN,
                            flex="1",
                        ),
                        rx.select(
                            ["Todos", "Petición", "Queja", "Reclamo", "Sugerencia"],
                            placeholder="Tipo de solicitud",
                            bg=INPUT_BG,
                            border=f"1px solid {INPUT_BDR}",
                            border_radius="8px",
                            font_size="13px",
                            color=TEXT_MAIN,
                            flex="1",
                        ),
                        rx.select(
                            ["Todos", "Atención al Ciudadano", "Contabilidad", "Bienestar", "Tesorería", "Secretaría"],
                            placeholder="Área responsable",
                            bg=INPUT_BG,
                            border=f"1px solid {INPUT_BDR}",
                            border_radius="8px",
                            font_size="13px",
                            color=TEXT_MAIN,
                            flex="1",
                        ),
                        spacing="3", align_items="center",
                        width="100%", flex_wrap="wrap",
                    ),
                    padding="14px 20px",
                ),
 
                # ── KPIs ─────────────────────────────────────────────────
                rx.grid(
                    _kpi("Total solicitudes",  State.numero_solicitudes,
                         BLUE_ACC, "files",        _ldc("#eff6ff", "#0f2744")),
                    _kpi("Radicadas",           State.numero_solicitudes_radicadas,
                         ORANGE,   "file-text",    _ldc("#fffbeb", "#2d1e00")),
                    _kpi("Actualizadas",        State.numero_solicitudes_actualizadas,
                         TEAL,     "refresh-cw",   _ldc("#f0fdfe", "#002030")),
                    _kpi("Cerradas",            State.numero_solicitudes_cerradas,
                         GREEN,    "check-circle", _ldc("#f0fdf4", "#002818")),
                    columns="4",
                    gap="4",
                    width="100%",
                    style={"gridTemplateColumns": "repeat(auto-fit, minmax(180px, 1fr))"},
                ),
 
                # ── Fila principal: gráficas + sidebar ────────────────────
                rx.hstack(
 
                    # Columna gráficas
                    rx.vstack(
 
                        # Solicitudes por Tipo
                        _chart_card(
                            "Solicitudes por Tipo",
                            "Distribución de PQRS por categoría",
                            "bar-chart-2", BLUE_ACC,
                            rc.bar_chart(
                                rc.x_axis(data_key="name", tick={"fontSize": 12}),
                                rc.y_axis(tick={"fontSize": 12}),
                                rc.tooltip(),
                                rc.bar(data_key="cantidad", fill=BLUE_ACC, radius=[6, 6, 0, 0]),
                                data=State.data_grafica_tipo,
                                width=520, height=280,
                            ),
                        ),
 
                        # Tiempos de respuesta
                        _chart_card(
                            "Tiempos de Respuesta",
                            "Días hábiles promedio — últimos 30 días",
                            "clock", TEAL,
                            rc.line_chart(
                                rc.x_axis(data_key="month", tick={"fontSize": 11}),
                                rc.y_axis(tick={"fontSize": 11}),
                                rc.tooltip(),
                                rc.cartesian_grid(stroke_dasharray="3 3", opacity=0.3),
                                rc.line(
                                    type="monotone",
                                    data_key="value",
                                    stroke=TEAL,
                                    stroke_width=2.5,
                                    dot={"r": 4, "fill": TEAL, "stroke": "white", "strokeWidth": 2},
                                ),
                                data=State.monthly_response_times,
                                width=520, height=260,
                            ),
                        ),
 
                        # Semáforo de plazos
                        _chart_card(
                            "Semáforo de Plazos",
                            "Solicitudes activas por días hábiles restantes",
                            "traffic-cone", ORANGE,
                            rx.cond(
                                State.semaforo_total,
                                rc.bar_chart(
                                    rc.x_axis(data_key="name", tick={"fontSize": 12}),
                                    rc.y_axis(tick={"fontSize": 12}),
                                    rc.tooltip(),
                                    rc.bar(data_key="verde",    fill=GREEN,  radius=[6,6,0,0]),
                                    rc.bar(data_key="amarillo", fill=ORANGE, radius=[6,6,0,0]),
                                    rc.bar(data_key="rojo",     fill=RED,    radius=[6,6,0,0]),
                                    data=State.semaforo_bar_data,
                                    width=520, height=240,
                                ),
                                rx.center(
                                    rx.text("No hay solicitudes activas.", color=TEXT_SUB, font_size="13px"),
                                    padding_y="40px", width="100%",
                                ),
                            ),
                        ),
 
                        # Cumplimiento
                        _chart_card(
                            "Nivel de Cumplimiento",
                            "Solicitudes resueltas dentro del plazo legal",
                            "shield-check", GREEN,
                            rx.hstack(
                                rc.pie_chart(
                                    rc.tooltip(),
                                    rc.pie(
                                        data_key="value",
                                        name_key="name",
                                        inner_radius="55%",
                                        outer_radius="80%",
                                    ),
                                    data=State.compliance_chart_data,
                                    width=220, height=220,
                                ),
                                rx.vstack(
                                    rx.text(
                                        State.compliance_percentage,
                                        font_size="3.5rem",
                                        font_weight="900",
                                        color=GREEN,
                                        line_height="1",
                                        letter_spacing="-0.04em",
                                    ),
                                    rx.text("%", font_size="1.2rem", font_weight="700", color=TEXT_SUB),
                                    rx.text("de cumplimiento", font_size="12px", color=TEXT_SUB),
                                    spacing="1", align_items="start",
                                ),
                                spacing="6", align_items="center",
                                width="100%",
                            ),
                        ),
 
                        spacing="4", align_items="stretch", flex="1", min_width="0",
                    ),
 
                    # Sidebar KPIs + Áreas
                    rx.vstack(
 
                        # Resumen numérico
                        _card(
                            rx.vstack(
                                rx.hstack(
                                    rx.icon("activity", size=14, color=BLUE_ACC),
                                    rx.text("Resumen", font_size="13px", font_weight="700", color=TEXT_MAIN),
                                    spacing="2", align_items="center",
                                ),
                                rx.divider(color=SECT_LINE),
                                rx.hstack(
                                    rx.text("Solicitudes totales", font_size="13px", color=TEXT_SUB, flex="1"),
                                    rx.text(State.numero_solicitudes, font_size="13px", font_weight="700", color=TEXT_MAIN),
                                    width="100%", align_items="center",
                                    padding_y="6px",
                                    border_bottom=f"1px solid {SECT_LINE}",
                                ),
                                rx.hstack(
                                    rx.text("Tiempo prom. cierre", font_size="13px", color=TEXT_SUB, flex="1"),
                                    rx.text("10 min", font_size="13px", font_weight="700", color=TEXT_MAIN),
                                    width="100%", align_items="center",
                                    padding_y="6px",
                                ),
                                spacing="3", align_items="stretch", width="100%",
                            ),
                            width="320px",
                        ),
 
                        # Mejores áreas
                        _card(
                            rx.vstack(
                                rx.hstack(
                                    rx.icon("building-2", size=14, color=VIOLET),
                                    rx.text("Áreas con más solicitudes", font_size="13px", font_weight="700", color=TEXT_MAIN),
                                    spacing="2", align_items="center",
                                ),
                                rx.divider(color=SECT_LINE),
                                rx.vstack(
                                    rx.foreach(State.top_areas, _area_row),
                                    spacing="0", width="100%",
                                ),
                                spacing="3", align_items="stretch", width="100%",
                            ),
                            width="320px",
                        ),
 
                        # Estados resumen
                        _card(
                            rx.vstack(
                                rx.hstack(
                                    rx.icon("layers", size=14, color=ORANGE),
                                    rx.text("Estados actuales", font_size="13px", font_weight="700", color=TEXT_MAIN),
                                    spacing="2", align_items="center",
                                ),
                                rx.divider(color=SECT_LINE),
                                rx.vstack(
                                    rx.foreach(
                                        State.data_grafica_estado,
                                        lambda row: rx.hstack(
                                            rx.box(
                                                width="10px", height="10px",
                                                border_radius="full",
                                                bg=rx.cond(
                                                    row.get("name") == "Radicada", ORANGE,
                                                    rx.cond(row.get("name") == "Actualizada", BLUE_ACC, GREEN),
                                                ),
                                                flex_shrink="0",
                                            ),
                                            rx.text(row.get("name", ""), font_size="13px", color=TEXT_MAIN, flex="1"),
                                            rx.text(row.get("cantidad", 0), font_size="13px", font_weight="700", color=TEXT_MAIN),
                                            spacing="3", align_items="center",
                                            padding_y="8px",
                                            border_bottom=f"1px solid {SECT_LINE}",
                                            width="100%",
                                        ),
                                    ),
                                    spacing="0", width="100%",
                                ),
                                spacing="3", align_items="stretch", width="100%",
                            ),
                            width="320px",
                        ),
 
                        spacing="4",
                        align_items="stretch",
                        width="320px",
                        flex_shrink="0",
                    ),
 
                    spacing="5",
                    align_items="start",
                    width="100%",
                    flex_wrap="wrap",
                ),
 
                spacing="5",
                align_items="stretch",
                width="100%",
                max_width="1280px",
                margin="0 auto",
            ),
            padding="24px",
            width="100%",
        ),
 
        bg=PAGE_BG,
        min_height="100vh",
        width="100%",
    )
 
    return rx.cond(
        State.es_autentica & (
            (State.rol_usuario == "funcionario") | (State.rol_usuario == "administrador")
        ),
        contenido,
        acceso_denegado,
    )


# ── Tokens ───────────────────────────────────────────────────────────────────
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)

PAGE_BG   = _ldc("#f1f5f9", "#0b1120")
CARD_BG   = _ldc("#ffffff", "#1e293b")
CARD_BDR  = _ldc("#e2e8f0", "#334155")
TH_BG     = _ldc("#f8fafc", "#0f172a")
ROW_HOVER = _ldc("#f0f7ff", "#1e3a5f22")
TEXT_MAIN = _ldc("#0f172a", "#f1f5f9")
TEXT_SUB  = _ldc("#64748b", "#94a3b8")
BLUE_ACC  = "#3b82f6"
NAVY      = "#1e3a8a"


def _th(label: str) -> rx.Component:
    """Encabezado de columna con estilo."""
    return rx.table.column_header_cell(
        rx.text(
            label,
            font_size="12px",
            font_weight="700",
            color=TEXT_SUB,
            text_transform="uppercase",
            letter_spacing="0.05em",
        ),
    )


def _user_table_row(usuario: dict) -> rx.Component:
    """Fila de la tabla con avatar icono + datos."""
    return rx.table.row(
        # Avatar / ícono
        rx.table.cell(
            rx.box(
                rx.icon("user", size=14, color="white"),
                width="32px",
                height="32px",
                border_radius="full",
                bg=rx.cond(usuario["rol"] == "funcionario", BLUE_ACC, "#64748b"),
                display="flex",
                align_items="center",
                justify_content="center",
                flex_shrink="0",
            ),
        ),
        # Email
        rx.table.cell(
            rx.text(
                usuario["email"],
                font_size="13px",
                font_weight="500",
                color=TEXT_MAIN,
                overflow="hidden",
                text_overflow="ellipsis",
                white_space="nowrap",
                max_width="280px",
            ),
        ),
        # Nombres
        rx.table.cell(
            rx.text(usuario["nombres"], font_size="13px", color=TEXT_MAIN),
        ),
        # Apellidos
        rx.table.cell(
            rx.text(usuario["apellidos"], font_size="13px", color=TEXT_MAIN),
        ),
        # Rol
        rx.table.cell(
            rx.badge(
                usuario["rol"],
                color_scheme=rx.cond(usuario["rol"] == "funcionario", "blue", "gray"),
                variant="soft",
                font_size="11px",
                border_radius="6px",
                padding_x="8px",
            ),
        ),
        # Fecha creación
        rx.table.cell(
            rx.text(usuario["fecha_creacion"], font_size="12px", color=TEXT_SUB),
        ),
        # Estado
        rx.table.cell(
            rx.badge(
                usuario["is_active"],
                color_scheme=rx.cond(usuario["is_active"] == "Activo", "green", "red"),
                variant="soft",
                font_size="11px",
                border_radius="6px",
            ),
        ),
        # Hover sutil
        _hover={"bg": ROW_HOVER},
        transition="background 0.15s ease",
    )


def usuarios_page() -> rx.Component:
    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("shield-x", size=48, color="#ef4444"),
            rx.heading("Acceso Denegado", size="7", color="#ef4444"),
            rx.text("Solo funcionarios autenticados pueden ver esta página.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )

    contenido = rx.box(
        navbar(),
        rx.box(
            rx.vstack(

                # ── Encabezado ────────────────────────────────────────────
                rx.hstack(
                    rx.hstack(
                        rx.box(
                            rx.icon("users", size=20, color="white"),
                            bg=NAVY,
                            border_radius="12px",
                            width="44px", height="44px",
                            display="flex", align_items="center", justify_content="center",
                        ),
                        rx.vstack(
                            rx.heading(
                                "Gestión de Usuarios",
                                size="6", color=TEXT_MAIN,
                                font_weight="800", letter_spacing="-0.02em",
                            ),
                            rx.text(
                                "Lista de usuarios registrados en el sistema",
                                font_size="13px", color=TEXT_SUB,
                            ),
                            spacing="0", align_items="start",
                        ),
                        spacing="3", align_items="center",
                    ),
                    rx.spacer(),
                    # Contador total
                    rx.box(
                        rx.vstack(
                            rx.text(
                                State.usuarios_registrados_count,
                                font_size="1.8rem", font_weight="800",
                                color=BLUE_ACC, line_height="1",
                            ),
                            rx.text("usuarios", font_size="12px", color=TEXT_SUB),
                            spacing="0", align_items="center",
                        ),
                        bg=CARD_BG,
                        border=f"1px solid {CARD_BDR}",
                        border_radius="14px",
                        padding="12px 20px",
                        text_align="center",
                    ),
                    width="100%", align_items="center",
                    flex_wrap="wrap", gap="3",
                ),

                # ── Tabla ─────────────────────────────────────────────────
                rx.box(
                    rx.cond(
                        State.usuarios_registrados,
                        rx.box(
                            rx.table.root(
                                # Encabezados
                                rx.table.header(
                                    rx.table.row(
                                        # Columna avatar sin label
                                        rx.table.column_header_cell(rx.text("")),
                                        _th("Email"),
                                        _th("Nombres"),
                                        _th("Apellidos"),
                                        _th("Rol"),
                                        _th("Fecha de Creación"),
                                        _th("Estado"),
                                        bg=TH_BG,
                                    ),
                                ),
                                # Filas
                                rx.table.body(
                                    rx.foreach(State.usuarios_registrados, _user_table_row),
                                ),
                                width="100%",
                                size="2",
                            ),
                            overflow_x="auto",
                            width="100%",
                        ),
                        # Estado vacío
                        rx.center(
                            rx.vstack(
                                rx.icon("user-x", size=40, color=TEXT_SUB),
                                rx.text(
                                    "No hay usuarios registrados aún.",
                                    color=TEXT_SUB, font_size="14px",
                                ),
                                spacing="3", align_items="center",
                            ),
                            padding_y="60px",
                        ),
                    ),
                    bg=CARD_BG,
                    border=f"1px solid {CARD_BDR}",
                    border_radius="16px",
                    box_shadow="0 1px 3px rgba(0,0,0,0.06), 0 4px 12px rgba(0,0,0,0.04)",
                    overflow="hidden",
                    width="100%",
                ),

                spacing="6",
                align_items="stretch",
                width="100%",
                max_width="1280px",
                margin="0 auto",
                padding="24px",
            ),
        ),
        bg=PAGE_BG,
        min_height="100vh",
        width="100%",
    )

    return rx.cond(
        State.es_autentica & (State.rol_usuario == "funcionario"),
        contenido,
        acceso_denegado,
    )


NAVY      = "#1e3a8a"
NAVY_DARK = "#172554"
BLUE_ACC  = "#2563eb"
GREEN     = "#16a34a"
GREEN_OK  = GREEN
RED_ERR   = "#dc2626"
UPLOAD_BG = _ldc("#f8fbff", "#071826")
UPLOAD_BDR= _ldc("#cfe7ff", "#12323a")
 
def _ldc(light, dark):
    return rx.color_mode_cond(light=light, dark=dark)
 
PAGE_BG   = _ldc("#f1f5f9", "#070d1a")
CARD_BG   = _ldc("#ffffff", "#0f1e35")
CARD_BDR  = _ldc("#e2e8f0", "#1e3a5f")
TEXT_MAIN = _ldc("#0f172a", "#f0f6ff")
TEXT_SUB  = _ldc("#64748b", "#7ea8c9")
INPUT_BG  = _ldc("#f8fafc", "#0a1628")
INPUT_BDR = _ldc("#d1d5db", "#1e3a5f")
 
 
def cambiar_rol_page() -> rx.Component:
    # Use the local `navbar` defined in this module
 
    acceso_denegado = rx.center(
        rx.vstack(
            rx.icon("shield-x", size=48, color=RED_ERR),
            rx.heading("Acceso Denegado", size="7", color=RED_ERR),
            rx.text("Solo funcionarios autenticados pueden acceder.", color=TEXT_SUB),
            rx.link(rx.button("Ir al Login", color_scheme="blue", border_radius="10px"), href="/login"),
            spacing="4", align_items="center",
        ),
        min_height="80vh",
    )
 
    contenido = rx.box(
        navbar(),
        rx.center(
            rx.box(
                rx.vstack(
                    # Encabezado con ícono
                    rx.vstack(
                        rx.box(
                            rx.icon("user-cog", size=28, color="white"),
                            bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                            border_radius="16px",
                            width="60px", height="60px",
                            display="flex", align_items="center", justify_content="center",
                            box_shadow=f"0 8px 24px {NAVY}55",
                        ),
                        rx.heading(
                            "Cambiar Rol de Usuario",
                            size="6", color=TEXT_MAIN,
                            font_weight="800", letter_spacing="-0.02em",
                            text_align="center",
                        ),
                        rx.text(
                            "Promueve a un ciudadano al rol de funcionario del sistema",
                            font_size="14px", color=TEXT_SUB, text_align="center",
                        ),
                        spacing="3", align_items="center", width="100%",
                    ),
                    # Tarjeta formulario
                    rx.box(
                        rx.vstack(
                            # Aviso informativo
                            rx.hstack(
                                rx.box(
                                    rx.icon("info", size=15, color=BLUE_ACC),
                                    width="30px", height="30px",
                                    border_radius="8px",
                                    bg=_ldc("#eff6ff", "#0f2744"),
                                    display="flex", align_items="center", justify_content="center",
                                    flex_shrink="0",
                                ),
                                rx.text(
                                    "Al promover un ciudadano, tendrá acceso al panel de "
                                    "funcionario y recibirá una notificación por correo.",
                                    font_size="13px", color=TEXT_SUB, line_height="1.6",
                                ),
                                spacing="3", align_items="start",
                                bg=_ldc("#eff6ff", "#0a1628"),
                                border=f"1px solid {_ldc('#bfdbfe','#1e3a5f')}",
                                border_radius="10px",
                                padding="12px 16px",
                                width="100%",
                            ),
                            # Campo correo
                            rx.vstack(
                                rx.hstack(
                                    rx.text("Correo del usuario a promover", font_size="13px", font_weight="600", color=TEXT_MAIN),
                                    rx.text("*", color="#e85d04", font_size="13px"),
                                    spacing="1",
                                ),
                                rx.box(
                                    rx.hstack(
                                        rx.icon("mail", size=16, color=TEXT_SUB),
                                        rx.input(
                                            placeholder="usuario@ejemplo.com",
                                            value=State.cambiar_rol_email,
                                            on_change=State.set_cambiar_rol_email,
                                            type="email",
                                            border="none",
                                            bg="transparent",
                                            color=TEXT_MAIN,
                                            font_size="14px",
                                            flex="1",
                                            _focus={"outline": "none"},
                                            _placeholder={"color": TEXT_SUB},
                                        ),
                                        spacing="2", align_items="center", width="100%",
                                    ),
                                    bg=INPUT_BG,
                                    border=f"1.5px solid {INPUT_BDR}",
                                    border_radius="10px",
                                    padding="10px 14px",
                                    width="100%",
                                    _focus_within={
                                        "border_color": BLUE_ACC,
                                        "box_shadow": "0 0 0 3px rgba(37,99,235,0.12)",
                                    },
                                ),
                                spacing="2", align_items="start", width="100%",
                            ),
                            # Mensaje resultado
                            rx.cond(
                                State.cambiar_rol_mensaje != "",
                                rx.hstack(
                                    rx.icon(
                                        rx.cond(State.cambiar_rol_mensaje.contains("✅"), "circle-check", "circle-x"),
                                        size=16,
                                        color=rx.cond(State.cambiar_rol_mensaje.contains("✅"), GREEN, RED_ERR),
                                    ),
                                    rx.text(
                                        State.cambiar_rol_mensaje,
                                        font_size="13px", font_weight="500",
                                        color=rx.cond(State.cambiar_rol_mensaje.contains("✅"), GREEN, RED_ERR),
                                    ),
                                    spacing="2", align_items="center",
                                    bg=rx.cond(State.cambiar_rol_mensaje.contains("✅"), _ldc("#f0fdf4","#002818"), _ldc("#fef2f2","#2d0000")),
                                    border=rx.cond(State.cambiar_rol_mensaje.contains("✅"), "1px solid #bbf7d0", "1px solid #fecaca"),
                                    border_radius="8px",
                                    padding="10px 14px",
                                    width="100%",
                                ),
                            ),
                            # Botón
                            rx.button(
                                rx.hstack(
                                    rx.icon("arrow-up-circle", size=16),
                                    rx.text("Promover a Funcionario", font_size="14px", font_weight="600"),
                                    spacing="2",
                                ),
                                on_click=State.cambiar_rol_ciudadano_a_funcionario,
                                width="100%", height="46px",
                                bg=f"linear-gradient(135deg, {NAVY_DARK}, {NAVY})",
                                color="white",
                                border_radius="10px",
                                box_shadow=f"0 4px 14px {NAVY}44",
                                _hover={"opacity": "0.92", "transform": "translateY(-1px)"},
                                transition="all 0.15s ease",
                                is_disabled=State.cambiar_rol_email == "",
                            ),
                            spacing="4", align_items="stretch", width="100%",
                        ),
                        bg=CARD_BG,
                        border=f"1px solid {CARD_BDR}",
                        border_radius="18px",
                        padding="28px 30px",
                        box_shadow=_ldc("0 4px 24px rgba(0,0,0,0.07)", "0 4px 32px rgba(0,0,0,0.4)"),
                        width="100%",
                    ),
                    spacing="6", align_items="center", width="100%",
                ),
                width="100%", max_width="480px",
                padding={"base": "24px 16px", "md": "48px 24px"},
            ),
            width="100%", min_height="90vh",
        ),
        bg=PAGE_BG, min_height="100vh", width="100%",
    )
 
    return rx.cond(
        State.es_autentica & (State.rol_usuario == "funcionario"),
        contenido, acceso_denegado,
    )


app = rx.App()
app.add_page(index, route="/", title="Inicio - Sistema PQRS")
app.add_page(registro_page, route="/registro", title="Registro de Ciudadano")
app.add_page(registro_funcionario_page, route="/registro-funcionario", title="Registro de Funcionario")
app.add_page(login_page, route="/login", title="Iniciar Sesión")
app.add_page(solicitudes_page, route="/solicitudes", title="Nueva Solicitud PQRS")
app.add_page(change_password_page, route="/cambiar-contrasena", title="Cambiar Contraseña")
app.add_page(dashboard, route="/dashboard", title="Panel de Ciudadano")
app.add_page(funcionario_dashboard, route="/dashboard-funcionario", title="Panel de Funcionario")
app.add_page(usuarios_page, route="/usuarios", title="Gestión de Usuarios")
app.add_page(cambiar_rol_page, route="/cambiar-rol", title="Cambiar Rol de Usuario")
app.add_page(consultar_estado_page, route="/consultar-estado", title="Consultar Estado de Solicitud")
app.add_page(politica_privacidad_page, route="/politica-privacidad", title="Política de Privacidad")
app.add_page(reportes_page, route="/reportes", title="Reportes PQRS", on_load=State.cargar_solicitudes)

if app._api is not None:
    app._api.mount(
        "/assets/uploads",
        StaticFiles(directory=str(UPLOAD_DIR), check_dir=False),
        name="uploads",
    )
    
    # Endpoints para descargas con "Guardar como"
    from starlette.responses import Response
    
    async def download_file(download_id: str):
        """Descarga un archivo del almacenamiento temporal."""
        try:
            if download_id not in TEMP_DOWNLOADS:
                return Response(
                    content=b"Archivo no encontrado o expirado",
                    status_code=404,
                    media_type="text/plain"
                )
            
            file_data = TEMP_DOWNLOADS[download_id]
            filename = file_data.get("filename", "descargar.bin")
            data = file_data.get("data", b"")
            mime = file_data.get("mime", "application/octet-stream")
            
            # Limpiar después de acceder (descarga única)
            del TEMP_DOWNLOADS[download_id]
            
            return Response(
                content=data,
                media_type=mime,
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        except Exception as e:
            print(f"Error en download_file: {e}")
            return Response(
                content=b"Error al descargar el archivo",
                status_code=500,
                media_type="text/plain"
            )
    
