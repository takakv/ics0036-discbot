from peewee import *

db = SqliteDatabase("ics0026.db")


class EGToken(Model):
    token = CharField()
    accepted = BooleanField()
    valid = BooleanField()
    author = CharField()

    class Meta:
        table_name = "egtoken"
        database = db


def connect():
    db.connect()
    print("Connected to DB!")
    db.create_tables([EGToken])
