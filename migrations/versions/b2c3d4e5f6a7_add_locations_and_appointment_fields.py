"""
add locations and appointment fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2025-10-28
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create locations tables
    op.create_table(
        'location',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=150), nullable=False),
        sa.Column('admin_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False)
    )
    op.create_table(
        'location_schedule',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('location_id', sa.Integer(), sa.ForeignKey('location.id'), nullable=False),
        sa.Column('weekday', sa.Integer(), nullable=False),
        sa.Column('start_time', sa.Time(), nullable=False),
        sa.Column('end_time', sa.Time(), nullable=False),
        sa.Column('break_start', sa.Time(), nullable=True),
        sa.Column('break_end', sa.Time(), nullable=True),
    )

    # Alter appointment fields
    with op.batch_alter_table('appointment') as batch_op:
        batch_op.alter_column('customer_id', existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column('service_id', existing_type=sa.Integer(), nullable=True)
        batch_op.add_column(sa.Column('location_id', sa.Integer(), sa.ForeignKey('location.id'), nullable=True))
        batch_op.add_column(sa.Column('descricao', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('duracao', sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('appointment') as batch_op:
        batch_op.drop_column('duracao')
        batch_op.drop_column('descricao')
        batch_op.drop_column('location_id')
        batch_op.alter_column('service_id', existing_type=sa.Integer(), nullable=False)
        batch_op.alter_column('customer_id', existing_type=sa.Integer(), nullable=False)

    op.drop_table('location_schedule')
    op.drop_table('location')
