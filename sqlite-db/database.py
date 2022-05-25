import sqlite3
import os

def db_create(conn):
  conn.execute('''
  CREATE TABLE IF NOT EXISTS CA
  (
    ID                      INTEGER PRIMARY KEY,
    NAME                    CHAR(100),
    DESCRIPTION             CHAR(1000),
    KEYNAME                 CHAR(200),
    PP                      CHAR(342),
    CURVE_ID                INTEGER,
    CERTIFICATE             CHAR(2731),
    CA_STATUS_ID            INTEGER,
    ENGINE_ID               INTEGER,
    REGISTERDATE            DATE,
    ENDDATE                 DATE,
    OPERATORID              INTEGER
  );''')

  conn.execute('''
   CREATE TABLE IF NOT EXISTS REGISTRATION
  (
    ID                      INTEGER PRIMARY KEY,
    REQUESTDATE             DATE,
    REQUESTSTATUS           INTEGER,
    CANONICALID             CHAR(2731),
    RECEIVEDATE             DATE,
    PUBKEY                  CHAR(342),
    APPPERMISSIONS          CHAR(342),
    CERTISSUEPERMISSIONS    CHAR(342),
    CERTREQUESTPERMISSIONS  CHAR(342)
  );
  ''')

  conn.execute('''
  CREATE TABLE IF NOT EXISTS enrollment 
  (
    id                      integer PRIMARY KEY autoincrement,
    request_date            DATE,
    request_type_id         integer,
    request_status_id       integer,
    certificate_id          CHAR(4000),
    eov                     DATE,
    received_date           DATE,
    processed_date          DATE,
    verification_pubkey     CHAR(342) ,
    encryption_pubkey       CHAR(342) ,
    app_permissions         CHAR(342) ,
    cert_issue_permissions  CHAR(342) ,
    cert_request_permissions CHAR(342) ,
    certificate             CHAR(4000) ,
    add_date                DATE,
    ea_id                   integer
  );
  ''')

  conn.execute('''
  INSERT INTO CA (ID, NAME, DESCRIPTION, KEYNAME, PP, CURVE_ID, CERTIFICATE,
  CA_STATUS_ID, ENGINE_ID, REGISTERDATE, ENDDATE, OPERATORID)
      VALUES (
      20, 
      'RootCA', 
      'Texas2', 
      'certificates/services/ca/RootSignKey.prv certificates/services/ca/RootEncKey.prv',
      'public point in base64',
      0,
      'gAMAgQBZgRN0ZXN0cm9vdGNhLnRlc3QuY29tAAAAAAAihf3MhgAtgwEBgALwAQKAAgJugAEBgAICcIACATgBAeCBAQMB/8AAgIPvTW886gCm3x7kMI0YsxmwV/86fndqjkK0fWYC3gvwdYCAgzUgptYqGdPMmag5z93ffHX0pIke8pgk+E9Bu4Bq1hvDgIBEMYDkjI2OOILRa5VZqYLUN2wCrAVkNA16KbLLK5DJ+bMjC0wMQ/U8WLx+HviU1bgd6cN0w4fi58WX7wrBVCFR',
      1,
      21,
      2022-05-10,
      2067-05-09,
      150
    );
  ''')

  conn.execute('''
  INSERT INTO REGISTRATION (ID, REQUESTDATE, REQUESTSTATUS, CANONICALID, RECEIVEDATE, PUBKEY, 
  APPPERMISSIONS, CERTISSUEPERMISSIONS, CERTREQUESTPERMISSIONS)
      VALUES (
      12, 
      2022-03-20, 
      1, 
      '536f6d65456e726f6c4372656443616e6f6e6963616c4e616d65',
      2022-04-19,
      "4 dddd",
      "4 cccc",
      "4 bbb",
      "4 aaaa"
    );
  ''')



  return conn

def db_print(conn):
    for row in conn.execute("SELECT * FROM CA"):
        print(row)

def db_select(conn, table, column, value):
    if column != 'id':
      value = f'"{value}"'
    cursor = conn.execute(f'SELECT * FROM {table} WHERE {column} = {value}')
    for row in cursor:
        return {col[0].lower() : value for value, col in zip(row, cursor.description)}

def db_insert(conn, table, columns, values):
    columns = ', '.join(columns)
    values = ', '.join(values)
    cursor = conn.execute(f'INSERT INTO {table} ({columns}) VALUES ({values})')
    return cursor.lastrowid

def db_update(conn, table, col_value_dict, id):
    set_statement = [f'{col} = {col_value_dict[col]}' for col in col_value_dict]
    set_statement = ', '.join(set_statement)
    print(f'UPDATE {table} SET {set_statement} WHERE id = {id}')
    conn.execute(f'UPDATE {table} SET {set_statement} WHERE id = {id}')


if __name__ == '__main__':
    print('Testing DB connection')
    db_conn = sqlite3.connect('massa.db', check_same_thread=False)
    for row in db_conn.execute("SELECT name FROM sqlite_schema"):
        print(row)