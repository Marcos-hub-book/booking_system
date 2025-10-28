"""
add service_location link table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2025-10-28
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'service_location',
        sa.Column('service_id', sa.Integer(), sa.ForeignKey('service.id'), primary_key=True),
        sa.Column('location_id', sa.Integer(), sa.ForeignKey('location.id'), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table('service_location')
