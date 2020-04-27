import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Preference(SqlAlchemyBase):
    __tablename__ = 'preferences'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer,
                                sqlalchemy.ForeignKey("users.id"))
    category = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    name = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    user = orm.relation('User')
