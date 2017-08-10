#!/bin/sh
rm test.sqlite
sqlite3 test.sqlite < create_tables.sql