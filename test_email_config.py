#!/usr/bin/env python3
"""
Script de prueba para verificar que los correos funcionan correctamente.
Ejecuta esto desde la carpeta PQRS-1:

    python test_email_config.py

"""

import os
import sys
import smtplib
from pathlib import Path
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Simular la carga del .env exactamente como lo hace la app
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env", override=True)

print("=" * 70)
print("🔍 PRUEBA DE CONFIGURACIÓN DE CORREOS")
print("=" * 70)

# Leer configuración
email_sender = os.getenv("EMAIL_SENDER")
email_password = os.getenv("EMAIL_PASSWORD")
smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
smtp_port = int(os.getenv("SMTP_PORT", "587"))
empresa_nombre = os.getenv("EMPRESA_NOMBRE", "Sistema PQRS")

print("\n1️⃣ VERIFICACIÓN DE VARIABLES DE ENTORNO")
print("-" * 70)
print(f"✓ EMAIL_SENDER:     {email_sender if email_sender else '❌ NO CONFIGURADO'}")
print(f"✓ EMAIL_PASSWORD:   {'✅ Configurado' if email_password else '❌ NO CONFIGURADO'} (longitud: {len(email_password or '')})")
print(f"✓ SMTP_SERVER:      {smtp_server}")
print(f"✓ SMTP_PORT:        {smtp_port}")
print(f"✓ EMPRESA_NOMBRE:   {empresa_nombre}")

# Validar configuración básica
print("\n2️⃣ VALIDACIÓN DE CREDENCIALES")
print("-" * 70)
if not email_sender:
    print("❌ ERROR: EMAIL_SENDER no está configurado en .env")
    sys.exit(1)

if not email_password:
    print("❌ ERROR: EMAIL_PASSWORD no está configurado en .env")
    sys.exit(1)

if len(email_password) < 16:
    print(f"⚠️  ADVERTENCIA: La contraseña tiene {len(email_password)} caracteres")
    print("   Gmail App Passwords deben tener exactamente 16 caracteres (sin espacios)")
    print("   Verifica que no haya espacios en EMAIL_PASSWORD")

print("✅ Credenciales cargadas correctamente")

# Intentar conexión SMTP
print("\n3️⃣ PRUEBA DE CONEXIÓN SMTP")
print("-" * 70)
try:
    print(f"📡 Conectando a {smtp_server}:{smtp_port}...")
    with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as servidor:
        print(f"✅ Conexión establecida")
        
        print(f"🔐 Enviando EHLO...")
        servidor.ehlo()
        print(f"✅ EHLO completado")
        
        print(f"🔒 Iniciando TLS...")
        servidor.starttls()
        print(f"✅ TLS iniciado")
        
        print(f"🔐 Enviando EHLO nuevamente...")
        servidor.ehlo()
        print(f"✅ EHLO completado")
        
        print(f"🔓 Intentando login...")
        servidor.login(email_sender, email_password)
        print(f"✅ Login exitoso")
        
    print("\n✅ TODAS LAS PRUEBAS PASARON")
    print("   Los correos deberían funcionar correctamente")
    
except smtplib.SMTPAuthenticationError as e:
    print(f"\n❌ ERROR DE AUTENTICACIÓN")
    print(f"   Las credenciales de Gmail son incorrectas o el acceso está bloqueado")
    print(f"   \n   Soluciones:")
    print(f"   1. Verifica que EMAIL_PASSWORD sea una App Password de Gmail (16 caracteres)")
    print(f"   2. Asegúrate de que 2FA (autenticación de dos factores) está habilitada")
    print(f"   3. No uses tu contraseña de Gmail normal, usa la App Password")
    print(f"\n   Detalles técnicos: {str(e)}")
    sys.exit(1)

except smtplib.SMTPConnectError as e:
    print(f"\n❌ ERROR DE CONEXIÓN")
    print(f"   No se pudo conectar al servidor SMTP")
    print(f"   Posibles causas:")
    print(f"   - Sin conexión a internet")
    print(f"   - Firewall bloqueando puerto {smtp_port}")
    print(f"   - VPN interfiriendo con la conexión")
    print(f"\n   Detalles técnicos: {str(e)}")
    sys.exit(1)

except TimeoutError as e:
    print(f"\n❌ TIMEOUT")
    print(f"   La conexión tardó más de 15 segundos")
    print(f"   El servidor SMTP podría estar lento o inaccesible")
    print(f"\n   Detalles técnicos: {str(e)}")
    sys.exit(1)

except Exception as e:
    print(f"\n❌ ERROR INESPERADO")
    print(f"   Tipo: {type(e).__name__}")
    print(f"   Detalle: {str(e)}")
    sys.exit(1)

# Prueba de envío (opcional)
print("\n4️⃣ ¿DESEAS ENVIAR UN CORREO DE PRUEBA?")
print("-" * 70)
respuesta = input("Ingresa tu correo (o presiona Enter para omitir): ").strip()

if respuesta:
    try:
        print(f"\n📧 Enviando correo de prueba a {respuesta}...")
        
        mensaje = MIMEMultipart("alternative")
        mensaje["Subject"] = "Prueba de Correo - Sistema PQRS"
        mensaje["From"] = email_sender
        mensaje["To"] = respuesta
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #f0f7ff; padding: 30px; border-radius: 10px;">
                    <h1 style="color: #1e40af;">✅ Prueba Exitosa</h1>
                    <p>Este correo fue enviado exitosamente desde el Sistema PQRS.</p>
                    <p>La configuración de correos está funcionando correctamente.</p>
                </div>
            </body>
        </html>
        """
        
        mensaje.attach(MIMEText(html, "html"))
        
        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as servidor:
            servidor.ehlo()
            servidor.starttls()
            servidor.ehlo()
            servidor.login(email_sender, email_password)
            servidor.sendmail(email_sender, respuesta, mensaje.as_string())
        
        print(f"✅ Correo enviado exitosamente a {respuesta}")
        print("\n🎉 TODO ESTÁ FUNCIONANDO CORRECTAMENTE")
        
    except Exception as e:
        print(f"❌ Error al enviar correo: {str(e)}")
        sys.exit(1)

print("\n" + "=" * 70)
print("Script finalizado correctamente")
print("=" * 70)
