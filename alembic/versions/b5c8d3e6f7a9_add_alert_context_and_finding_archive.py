"""add_alert_context_and_finding_archive

Revision ID: b5c8d3e6f7a9
Revises: a3b7c1d2e4f5
Create Date: 2026-03-31

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5c8d3e6f7a9'
down_revision: Union[str, None] = 'a3b7c1d2e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Alert context column for rich event detail
    op.add_column('alerts', sa.Column('context', sa.JSON(), nullable=True))

    # FindingArchive table — lightweight long-term preservation of findings
    op.create_table(
        'finding_archives',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('original_id', sa.Integer(), nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
        sa.Column('rule_name', sa.String(64), nullable=True),
        sa.Column('device_id', sa.String(17), nullable=True),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('confidence', sa.String(16), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('likely_cause', sa.Text(), nullable=True),
        sa.Column('recommended_action', sa.Text(), nullable=True),
        sa.Column('outcome', sa.String(16), nullable=True),
        sa.Column('source', sa.String(16), nullable=False, server_default='agent'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_finding_archives_ts', 'finding_archives', ['ts'])
    op.create_index('ix_finding_archives_original_id', 'finding_archives', ['original_id'])


def downgrade() -> None:
    op.drop_table('finding_archives')
    op.drop_column('alerts', 'context')
