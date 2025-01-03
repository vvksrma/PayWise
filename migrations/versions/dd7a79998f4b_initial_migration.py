"""Initial migration

Revision ID: dd7a79998f4b
Revises: 
Create Date: 2025-01-03 20:43:22.310761

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dd7a79998f4b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('mobile_number', sa.String(length=15), nullable=False),
    sa.Column('password', sa.String(length=200), nullable=False),
    sa.Column('balance', sa.Float(), nullable=True),
    sa.Column('account_number', sa.String(length=12), nullable=False),
    sa.Column('customer_id', sa.String(length=6), nullable=False),
    sa.CheckConstraint('balance >= 0', name='check_user_balance'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('account_number'),
    sa.UniqueConstraint('customer_id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('email', name='uq_user_email'),
    sa.UniqueConstraint('mobile_number'),
    sa.UniqueConstraint('mobile_number', name='uq_user_mobile_number'),
    sa.UniqueConstraint('username')
    )
    op.create_table('money_request',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sender_id', sa.Integer(), nullable=False),
    sa.Column('recipient_id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['recipient_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['sender_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('transaction',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('type', sa.String(length=10), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('transaction')
    op.drop_table('money_request')
    op.drop_table('user')
    # ### end Alembic commands ###