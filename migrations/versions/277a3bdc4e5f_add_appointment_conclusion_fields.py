"""add appointment conclusion fields

Revision ID: 277a3bdc4e5f
Revises: 16920fe072ef
Create Date: 2026-04-27 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '277a3bdc4e5f'
down_revision = '16920fe072ef'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('appointment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('concluido', sa.Boolean(), nullable=True, server_default=sa.false()))
        batch_op.add_column(sa.Column('valor_real', sa.Numeric(10, 2), nullable=True))
        batch_op.add_column(sa.Column('forma_pagamento', sa.String(length=50), nullable=True))
    # set default false for existing rows
    op.execute("UPDATE appointment SET concluido = false WHERE concluido IS NULL")


def downgrade():
    with op.batch_alter_table('appointment', schema=None) as batch_op:
        batch_op.drop_column('forma_pagamento')
        batch_op.drop_column('valor_real')
        batch_op.drop_column('concluido')
