#myproject/utils/db.py
from django.db import connection

from contextlib import contextmanager

@contextmanager
def get_cursor_dict():
    cursor = connection.cursor()
    try:
        yield DictCursor(cursor)
    finally:
        cursor.close()

class DictCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, *args, **kwargs):
        return self.cursor.execute(*args, **kwargs)

    def fetchall(self):
        columns = [col[0] for col in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @property
    def rowcount(self):
        return self.cursor.rowcount