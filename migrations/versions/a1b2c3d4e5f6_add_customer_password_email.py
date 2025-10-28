"""
add customer password and email

Revision ID: a1b2c3d4e5f6
Revises: 682f7c2b18a5
Create Date: 2025-10-28
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '682f7c2b18a5'
branch_labels = None
depends_on = None

def upgrade() -> None:
    with op.batch_alter_table('customer') as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=150), nullable=True))
        batch_op.add_column(sa.Column('password', sa.String(length=255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('customer') as batch_op:
        batch_op.drop_column('password')
        batch_op.drop_column('email')
