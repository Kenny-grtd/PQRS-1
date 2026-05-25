# 🔧 Configuración de Envío de Correos con Gmail

## El Problema
Gmail eliminó el acceso con contraseña normal para aplicaciones SMTP a partir de mayo de 2022. Ahora **requiere una "App Password"** (contraseña de aplicación) de 16 caracteres.

## Solución: Obtener una App Password de Gmail

### Paso 1: Habilita la autenticación de dos factores en tu cuenta Gmail
1. Dirígete a [Google Account](https://myaccount.google.com/)
2. En el menú izquierdo, haz clic en **"Seguridad"** (Security)
3. Desplázate hasta **"Cómo accedes a Google"** (How you sign in to Google)
4. Activa **"Verificación en dos pasos"** (2-Step Verification)
   - Sigue las instrucciones en pantalla
   - Se te pedirá confirmar con tu teléfono

### Paso 2: Genera una App Password
1. Después de habilitar 2FA, vuelve a [Google Account > Seguridad](https://myaccount.google.com/security)
2. Desplázate hasta **"Contraseñas de aplicaciones"** (App passwords)
   - Si no ves esta opción, asegúrate de haber habilitado la verificación en dos pasos
3. Selecciona:
   - **Aplicación:** Mail (Correo)
   - **Dispositivo:** Windows / Mac / Linux (lo que uses)
4. Haz clic en **"Generar"**
5. Google te mostrará una contraseña de **16 caracteres** como esta:
   ```
   abcd efgh ijkl mnop
   ```
6. **Copia esta contraseña** (sin espacios): `abcdefghijklmnop`

### Paso 3: Configura el archivo .env
1. Abre o crea el archivo `.env` en la raíz del proyecto (`PQRS-1/.env`)
2. Reemplaza `EMAIL_PASSWORD` con los 16 caracteres que Google te dio (sin espacios):

```env
EMAIL_SENDER=tu_correo@gmail.com
EMAIL_PASSWORD=abcdefghijklmnop
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMPRESA_NOMBRE=Sistema PQRS
```

**⚠️ IMPORTANTE:**
- **Nunca compartas este .env** públicamente
- El `.env` está en `.gitignore` (no se sube a Git)
- Los 16 caracteres no tienen espacios

### Paso 4: Verifica que funciona
Cuando inicies la aplicación con `reflex run`, deberías ver en la terminal:

```
[EMAIL] SENDER configurado: True
[EMAIL] PASSWORD configurado: True
[EMAIL] SMTP_SERVER: smtp.gmail.com
[EMAIL] SMTP_PORT: 587
```

Si ves `False` en alguno, el .env no se cargó correctamente.

## Prueba de Envío de Correo

Para verificar que funciona, regístrate en la plataforma. En la terminal deberías ver:

✅ **Si funciona:**
```
[EMAIL] Intentando enviar correo de bienvenida a: usuario@example.com
✅ [EMAIL] Correo de bienvenida enviado exitosamente a usuario@example.com
```

❌ **Si falla (errores comunes):**

### Error: "Username and Password not accepted"
**Causa:** No usaste la App Password correctamente.
**Solución:**
- Copia nuevamente los 16 caracteres de Google
- Elimina cualquier espacio
- Asegúrate de que 2FA esté habilitado

### Error: "Connection refused" 
**Causa:** El servidor SMTP de Gmail no es accesible.
**Solución:**
- Verifica tu conexión a internet
- Gmail podría estar bloqueado por tu firewall/VPN
- Prueba desactivar el VPN temporalmente

### Error: "Less secure app access"
**Causa:** Ya no existe (Google lo quitó), pero si ves este mensaje es por cache.
**Solución:**
- Limpia la caché del navegador
- Usa la App Password, no tu contraseña normal

## 🎯 Resumen del Código Corregido

El código ahora:
1. ✅ Lee `.env` desde la ruta correcta: `BASE_DIR / ".env"`
2. ✅ Muestra prints de diagnóstico al iniciar
3. ✅ Valida credenciales antes de intentar enviar
4. ✅ Usa timeout de 15 segundos (evita bloqueos infinitos)
5. ✅ Llama `ehlo()` antes y después de `starttls()` (protocolo SMTP correcto)
6. ✅ Captura errores específicos (Autenticación, Conexión, Timeout)
7. ✅ Los errores de correo NO interrumpen el registro (usuario se crea de todas formas)
8. ✅ Funciona con App Passwords de 16 caracteres

## 📧 Flujo del Registro (Ahora Más Robusto)

```
Usuario se registra
    ↓
Usuario se guarda en BD ✅
    ↓
Se intenta enviar correo de bienvenida
    ↓
    ├─ Si funciona → ✅ Imprime éxito en logs
    └─ Si falla → ⚠️ Imprime error en logs, pero usuario sigue registrado
    ↓
Registro completa normalmente
```

## 🔍 Diagnóstico Avanzado

Si tienes problemas, ejecuta esto en la terminal Python:

```python
import os
from dotenv import load_dotenv
from pathlib import Path

# Simular cómo lo hace tu app
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env", override=True)

print(f"EMAIL_SENDER: {os.getenv('EMAIL_SENDER')}")
print(f"EMAIL_PASSWORD (primeros 5 chars): {os.getenv('EMAIL_PASSWORD', '')[:5]}...")
print(f"SMTP_SERVER: {os.getenv('SMTP_SERVER')}")
print(f"SMTP_PORT: {os.getenv('SMTP_PORT')}")
```

Debería mostrar todos los valores configurados (excepto la contraseña completa).

---

**¿Preguntas?** Revisa los logs en la terminal cuando ejecutes `reflex run`. El código ahora es muy específico en los mensajes de error.
