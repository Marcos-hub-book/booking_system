"""add salon buttons

Revision ID: c8f9d0e1a2b3
Revises: 7ee0f5608a8e
Create Date: 2026-10-23 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8f9d0e1a2b3'
down_revision = '7ee0f5608a8e'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'salon_button',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('admin_id', sa.Integer(), nullable=False),
        sa.Column('button_type', sa.String(length=32), nullable=False, server_default='custom'),
        sa.Column('title', sa.String(length=80), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('phone', sa.String(length=30), nullable=True),
        sa.Column('address', sa.String(length=255), nullable=True),
        sa.Column('url', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['admin_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('salon_button')
