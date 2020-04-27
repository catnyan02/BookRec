import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Exchange(SqlAlchemyBase):
    __tablename__ = 'exchanges'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    from_user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False)
    to_user_id = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    paired_exchange_id = sqlalchemy.Column(sqlalchemy.Integer)
    user_description = sqlalchemy.Column(sqlalchemy.String)
    book_id = sqlalchemy.Column(sqlalchemy.String)
    book_name = sqlalchemy.Column(sqlalchemy.String)
    current = sqlalchemy.Column(sqlalchemy.BOOLEAN, default=True)
    messages = orm.relation("Message", back_populates='exchange')
    from_user = orm.relation('User')
