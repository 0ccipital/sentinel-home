"""add_event_indexes

Revision ID: c1d2e3f4a5b6
Revises: b5c8d3e6f7a9
Create Date: 2026-04-02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, None] = 'b5c8d3e6f7a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Index Event.device_id for device-filtered event queries (device detail page,
    # actor recent-events lookup) and Event.rule_id for rule-filtered queries.
    # These are FK columns that SQLAlchemy does not auto-index in SQLite.
    op.create_index('ix_events_device_id', 'events', ['device_id'])
    op.create_index('ix_events_rule_id', 'events', ['rule_id'])


def downgrade() -> None:
    op.drop_index('ix_events_device_id', table_name='events')
    op.drop_index('ix_events_rule_id', table_name='events')
