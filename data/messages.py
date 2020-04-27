import datetime

import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Message(SqlAlchemyBase):
    __tablename__ = 'messages'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    exchange_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("exchanges.id"))
    message = sqlalchemy.Column(sqlalchemy.String)
    time_sent = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.now)
    exchange = orm.relation('Exchange')
