"""
Drop unique constraint on user.company_name (allow duplicate company names)

Revision ID: ab12cd34ef56
Revises: e1f2a3b4c5d6
Create Date: 2025-11-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = 'ab12cd34ef56'
down_revision = 'e1f2a3b4c5d6'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = inspect(bind)
    # Try to find a unique constraint on company_name and drop it by name if present
    try:
        uniques = insp.get_unique_constraints('user')
    except Exception:
        uniques = []
    dropped = False
    for uc in uniques:
        cols = set(uc.get('column_names') or [])
        name = uc.get('name')
        if cols == {'company_name'} and name:
            op.drop_constraint(name, 'user', type_='unique')
            dropped = True
            break
    # Fallback for dialects that don't report names (e.g., SQLite): recreate table without the unique
    if not dropped:
        with op.batch_alter_table('user', recreate='always') as batch_op:
            # Recreate the remaining uniques we still want to enforce explicitly
            # Ensure username and email remain unique
            batch_op.create_unique_constraint('uq_user_username', ['username'])
            batch_op.create_unique_constraint('uq_user_email', ['email'])
            # Do NOT recreate unique on company_name


def downgrade():
    # Recreate a unique constraint on company_name if needed
    bind = op.get_bind()
    insp = inspect(bind)
    # Only add if not already present
    try:
        uniques = insp.get_unique_constraints('user')
    except Exception:
        uniques = []
    has_company_unique = any(set(uc.get('column_names') or []) == {'company_name'} for uc in uniques)
    if not has_company_unique:
        try:
            op.create_unique_constraint('uq_user_company_name', 'user', ['company_name'])
        except Exception:
            # Fallback recreate to enforce again
            with op.batch_alter_table('user', recreate='always') as batch_op:
                batch_op.create_unique_constraint('uq_user_username', ['username'])
                batch_op.create_unique_constraint('uq_user_email', ['email'])
                batch_op.create_unique_constraint('uq_user_company_name', ['company_name'])
