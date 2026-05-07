"""Initial migration

Revision ID: 001_initial
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table('users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(100), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), server_default='analyst'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_users_username', 'users', ['username'])

    # Vendors
    op.create_table('vendors',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('bin_code', sa.String(50), unique=True, nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_vendors_name', 'vendors', ['name'])

    # Scan Jobs
    op.create_table('scan_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('target_domain', sa.String(255), nullable=False),
        sa.Column('status', sa.Enum('pending', 'running', 'completed', 'failed', name='scanstatus'), server_default='pending'),
        sa.Column('progress', sa.Integer(), server_default='0'),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('result', postgresql.JSONB(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Hosts
    op.create_table('hosts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('domain', sa.String(255), nullable=True),
        sa.Column('vendor_id', sa.Integer(), sa.ForeignKey('vendors.id'), nullable=True),
        sa.Column('geolocation', postgresql.JSONB(), nullable=True),
        sa.Column('scan_job_id', sa.Integer(), sa.ForeignKey('scan_jobs.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_hosts_ip', 'hosts', ['ip_address'])
    op.create_index('ix_hosts_domain', 'hosts', ['domain'])

    # Services
    op.create_table('services',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(20), server_default='tcp'),
        sa.Column('service_name', sa.String(100), nullable=True),
        sa.Column('banner_data', postgresql.JSONB(), nullable=True),
        sa.Column('classification', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Vulnerabilities
    op.create_table('vulnerabilities',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('service_id', sa.Integer(), sa.ForeignKey('services.id'), nullable=True),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('privacy_risk_type', sa.String(100), nullable=True),
        sa.Column('risk_score', sa.Float(), server_default='0'),
        sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='severitylevel'), server_default='low'),
        sa.Column('title', sa.String(500), nullable=True),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('vulnerabilities')
    op.drop_table('services')
    op.drop_table('hosts')
    op.drop_table('scan_jobs')
    op.drop_table('vendors')
    op.drop_table('users')
    op.execute('DROP TYPE IF EXISTS scanstatus')
    op.execute('DROP TYPE IF EXISTS severitylevel')
