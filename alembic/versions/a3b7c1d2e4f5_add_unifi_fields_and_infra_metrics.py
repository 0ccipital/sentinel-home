"""add_unifi_fields_and_infra_metrics

Revision ID: a3b7c1d2e4f5
Revises: 060d94ea7c08
Create Date: 2026-03-26

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3b7c1d2e4f5'
down_revision: Union[str, Sequence[str], None] = '060d94ea7c08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add UniFi integration columns to devices and create infra_metrics table."""
    # New columns on devices table
    with op.batch_alter_table("devices") as batch_op:
        batch_op.add_column(sa.Column("signal_strength", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("channel", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("band", sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column("unifi_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("vlan_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("infra_state", sa.String(length=32), nullable=True))

    # Infrastructure metrics time-series table
    op.create_table(
        "infra_metrics",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("device_mac", sa.String(length=17), nullable=False),
        sa.Column("cpu_load_1m", sa.Float(), nullable=True),
        sa.Column("cpu_load_5m", sa.Float(), nullable=True),
        sa.Column("memory_pct", sa.Float(), nullable=True),
        sa.Column("uplink_tx_bps", sa.Integer(), nullable=True),
        sa.Column("uplink_rx_bps", sa.Integer(), nullable=True),
        sa.Column("radio_tx_retries_pct", sa.Float(), nullable=True),
        sa.Column("uptime_seconds", sa.Integer(), nullable=True),
        sa.Column("client_count", sa.Integer(), nullable=True),
        sa.Column("raw", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["device_mac"], ["devices.mac"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_infra_metrics_ts", "infra_metrics", ["ts"])
    op.create_index("ix_infra_metrics_device_mac", "infra_metrics", ["device_mac"])


def downgrade() -> None:
    """Remove UniFi fields and infra_metrics table."""
    op.drop_index("ix_infra_metrics_device_mac", table_name="infra_metrics")
    op.drop_index("ix_infra_metrics_ts", table_name="infra_metrics")
    op.drop_table("infra_metrics")

    with op.batch_alter_table("devices") as batch_op:
        batch_op.drop_column("infra_state")
        batch_op.drop_column("vlan_id")
        batch_op.drop_column("unifi_id")
        batch_op.drop_column("band")
        batch_op.drop_column("channel")
        batch_op.drop_column("signal_strength")
