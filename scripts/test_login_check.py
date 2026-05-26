import sys
from pathlib import Path
# Asegurar que el directorio raíz del proyecto esté en sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sys
from pathlib import Path
from autenticacion import autenticacion as a
from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

pairs = [
    ('funcionario_test@example.com', 'Funcionario@2024'),
    ('funcionario_correcto@example.com', 'Funcionario2024'),
]

with Session(a.engine) as s:
    for email, password in pairs:
        user = s.exec(select(a.Usuario).where(a.Usuario.email == email)).first()
        if not user:
            print(f'Usuario no encontrado: {email}')
            continue
        print(f'Usuario encontrado: {user.email}')
        print(f'Hash almacenado: {user.Contraseña}')
        print(f'confirmar_contraseña: {a.confirmar_contraseña(password, user.Contraseña)}')
