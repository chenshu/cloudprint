#!/usr/bin/env python

import sqlite3
import itertools
import logging

class Connection(object):

    def __init__(self, filename, isolation_level=None):
        self.filename = filename
        self.isolation_level = isolation_level
        self._db = None
        try:
            self.reconnect()
        except:
            logging.error("Cannot connect to SQLite on %s", self.filename, exc_info=True)
            raise

    def __del__(self):
        self.close()

    def close(self):
        if getattr(self, "_db", None) is not None:
            self._db.close()
            self._db = None

    def reconnect(self):
        self.close()
        self._db = sqlite3.connect(self.filename)
        self._db.isolation_level = self.isolation_level

    def _cursor(self):
        if self._db is None:
            self.reconnect()
        return self._db.cursor()

    def _execute(self, cursor, query, parameters):
        try:
            return cursor.execute(query, parameters)
        except OperationalError:
            logging.error("Error connecting to SQLite on %s", self.filename)
            self.close()
            raise

    def query(self, query, *parameters):
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters)
            column_names = [d[0] for d in cursor.description]
            return [Row(itertools.izip(column_names, row)) for row in cursor]
        finally:
            cursor.close()

    def get(self, query, *parameters):
        rows = self.query(query, *parameters)
        if not rows:
            return None
        elif len(rows) > 1:
            raise Exception("Multiple rows returned for Sqlite.get() query")
        else:
            return rows[0]

    def execute(self, query, *parameters):
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters)
            return cursor.lastrowid
        finally:
            cursor.close()

    def executemany(self, query, *parameters):
        cursor = self._cursor()
        try:
            cursor.executemany(query, parameters)
            return cursor.lastrowid
        finally:
            cursor.close()

class Row(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

OperationalError = sqlite3.OperationalError
