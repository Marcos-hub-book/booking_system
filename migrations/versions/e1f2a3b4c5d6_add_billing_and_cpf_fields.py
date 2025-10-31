"""
add billing and cpf fields

Revision ID: e1f2a3b4c5d6
Revises: f7325e9c937a
Create Date: 2025-10-29 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e1f2a3b4c5d6'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column('cpf_encrypted', sa.String(length=256), nullable=True))
        batch_op.add_column(sa.Column('cpf_hash', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('trial_started_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('trial_ends_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('trial_consumed', sa.Boolean(), nullable=True, server_default=sa.text('false')))
        batch_op.add_column(sa.Column('subscription_status', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('subscription_provider', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('subscription_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('current_period_end_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('canceled_at', sa.DateTime(), nullable=True))
        batch_op.create_index('ix_user_cpf_hash', ['cpf_hash'], unique=False)


def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_index('ix_user_cpf_hash')
        batch_op.drop_column('canceled_at')
        batch_op.drop_column('current_period_end_at')
        batch_op.drop_column('subscription_id')
        batch_op.drop_column('subscription_provider')
        batch_op.drop_column('subscription_status')
        batch_op.drop_column('trial_consumed')
        batch_op.drop_column('trial_ends_at')
        batch_op.drop_column('trial_started_at')
        batch_op.drop_column('cpf_hash')
        batch_op.drop_column('cpf_encrypted')
