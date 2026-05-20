"""Add extended user fields

Revision ID: add_user_fields_20260423
Revises: ff383e22d5c3_
Create Date: 2026-04-23 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_user_fields_20260423'
down_revision = 'ff383e22d5c3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('usuario', sa.Column('tipo_identificacion', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('numero_identificacion', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('nombres', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('apellidos', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('genero', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('direccion', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('telefono', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('departamento', sa.String(), nullable=True))
    op.add_column('usuario', sa.Column('ciudad', sa.String(), nullable=True))


def downgrade():
    op.drop_column('usuario', 'ciudad')
    op.drop_column('usuario', 'departamento')
    op.drop_column('usuario', 'telefono')
    op.drop_column('usuario', 'direccion')
    op.drop_column('usuario', 'genero')
    op.drop_column('usuario', 'apellidos')
    op.drop_column('usuario', 'nombres')
    op.drop_column('usuario', 'numero_identificacion')
    op.drop_column('usuario', 'tipo_identificacion')
