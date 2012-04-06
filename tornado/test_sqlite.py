#!/usr/bin/python

import os
import sys
import sqlite
import unittest
import datetime

sys.dont_write_bytecode = True

class TestSQLite(unittest.TestCase):
    def setUp(self):
        # self.path = '/tmp/test_db.db'
        self.path = ':memory:'
        self.db = sqlite.Connection(self.path)

    def tearDown(self):
        self.db.close()

    def tetConnection(self):
        self.assertNotEqual(self.db._db, None)

    def testReconnection(self):
        self.db.reconnect()
        self.assertNotEqual(self.db._db, None)

    def testCreateInsert(self):
        self.db.execute('''create table stocks (date text, trans text, symbol text, qty real, price real)''')
        self.db.execute('insert into stocks values (?, ?, ?, ?, ?)', '2006-01-05', 'BUY', 'RHAT', 100, 35.14)
        result = self.db.get('select * from stocks')
        print result
        result = self.db.query('select * from stocks')
        print result
        self.assertNotEqual(result, [])

if __name__ == '__main__':
    unittest.main()
