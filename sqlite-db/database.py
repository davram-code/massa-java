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

###################### ENROLLMENT AUTHORITY ######################
  conn.execute('''
  CREATE TABLE IF NOT EXISTS ea (
      id                      INTEGER PRIMARY KEY,
      name                    CHAR(1000) ,
      description             CHAR(1000) ,
      enc_prv_key                CHAR(1000) ,
      enc_pub_key                CHAR(1000) ,
      sgn_prv_key                CHAR(1000) ,
      sgn_pub_key                CHAR(1000) ,
      pp                      CHAR(342) ,
      curve_id                integer ,
      certificate             CHAR(2731) ,
      ea_status_id            integer ,
      engine_id               integer ,
      register_date           date,
      end_date                date,
      operator_id             integer ,
      add_date                date
  );
  ''')

  conn.execute('''
   CREATE TABLE IF NOT EXISTS REGISTRATION (
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

  conn.execute('''
  INSERT INTO EA (id, name, description, enc_prv_key, enc_pub_key, sgn_prv_key, sgn_pub_key, ea_status_id)
      VALUES (
      7,
      "ea.mta.ro",
      "This is Dimas EA",
      "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgFgr3bAURZRuZaai4g5DEpuD9IxClNOKvukZSq251+qagCgYIKoZIzj0DAQehRANCAAQxpwmvsvVYriaRYsyg1E4L3HYIlq0sPR5GV5ddV8sO7lGL47e8AzOnuDxGHJsvLA7VlhX9NKwfMOxtNkX/wxeQ",
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMacJr7L1WK4mkWLMoNROC9x2CJatLD0eRleXXVfLDu5Ri+O3vAMzp7g8RhybLywO1ZYV/TSsHzDsbTZF/8MXkA==",
      "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg/2mSR8pZ9/uB9rcNxmxMc+JunEkIETFIQ3OBoBjSK+ugCgYIKoZIzj0DAQehRANCAAThkpyeMUKxQYVUF5CtXFwOCqDAZr4947XnyvAIvpyRkCaeGSe4c3aRYpUQjq6ovEsLhxKC7Oro3XnjT5rq+HCi",
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4ZKcnjFCsUGFVBeQrVxcDgqgwGa+PeO158rwCL6ckZAmnhknuHN2kWKVEI6uqLxLC4cSguzq6N1540+a6vhwog==",
      0
    );
  ''')

###################### AUTHORIZATION AUTHORITY ######################

  conn.execute('''
  CREATE TABLE IF NOT EXISTS authorizations_requests (
      id                          integer PRIMARY KEY autoincrement,
      request_date                date,
      request_status              integer ,
      ea_id                       CHAR(342) ,
      key_tag                     CHAR(342) ,
      certificate_format          CHAR(342) ,
      requested_subject_attribute CHAR(342) ,
      eov                         date ,
      received_date               date,
      processed_date              date,
      verification_pubkey         CHAR(342) ,
      encryption_pubkey           CHAR(342) ,
      app_permissions             CHAR(342),
      cert_issue_permissions      CHAR(342) ,
      cert_request_permissions    CHAR(342) ,
      certificate                 text ,
      aa_id                       integer ,
      add_date                    date
  );
  ''')

  conn.execute('''
  CREATE TABLE IF NOT EXISTS aa (
      id                      INTEGER PRIMARY KEY,
      name                    CHAR(1000) ,
      description             CHAR(1000) ,
      enc_prv_key                CHAR(1000) ,
      enc_pub_key                CHAR(1000) ,
      sgn_prv_key                CHAR(1000) ,
      sgn_pub_key                CHAR(1000) ,
      pp                      CHAR(342) ,
      curve_id                integer ,
      certificate             CHAR(2731) ,
      ea_status_id            integer ,
      engine_id               integer ,
      register_date           date,
      end_date                date,
      operator_id             integer ,
      add_date                date
  );
  ''')

  conn.execute('''
  INSERT INTO AA (id, name, description, enc_prv_key, enc_pub_key, sgn_prv_key, sgn_pub_key, ea_status_id)
      VALUES (
      5,
      "aa.mta.ro",
      "This is Dimas AA",
      "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgeb3aFHB0XLh4LMKSimjW//679qnt3QPSFg7eZxh7wzigCgYIKoZIzj0DAQehRANCAARy2XbirEBdS0DSdpTuMDpbiLorygQvoSFjcQFF9UTystYSWt4VPdj4Mb+qo7KXFIDfkukxAGBByKjG4GHrJc3y",
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEctl24qxAXUtA0naU7jA6W4i6K8oEL6EhY3EBRfVE8rLWElreFT3Y+DG/qqOylxSA35LpMQBgQcioxuBh6yXN8g==",
      "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgbZhfSiEi+c1p3Nj5bfb1+qK4qD/I4hHJhKlfGoMvn/ygCgYIKoZIzj0DAQehRANCAAQFY/cl4eLnsBVe0ApCmmjcGAvWELAkAd28txWEibUCaeJrSuDWhGfxqC4585s/S++dA25wFEQ1+ktC4u6ldcpt",
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBWP3JeHi57AVXtAKQppo3BgL1hCwJAHdvLcVhIm1Amnia0rg1oRn8aguOfObP0vvnQNucBRENfpLQuLupXXKbQ==",
      0
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