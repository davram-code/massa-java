from flask import Flask, request
from database import db_create, db_select, db_insert, db_update
import sqlite3
import json
import base64

app = Flask(__name__)
db_conn = sqlite3.connect('massa.db', check_same_thread=False)


def get_first_attribute_value_pair_in_request(request):
    for arg in request.args:
        attribute = arg
        value = request.args.get(attribute)
        return attribute, value

def get_row_by_attribute_as_json(table, attribute, value):
    row = db_select(db_conn, table, attribute, value)
    row["success"] = "true"
    return json.dumps(row)

def stringify(val):
    return f'\"{val}\"' if isinstance(val, str) else str(val)


def insert_row(table, json_dict):
    values = [stringify(val) for val in json_dict.values()]
    id = db_insert(db_conn, table, json_dict.keys(), values)
    return json.dumps({"id" : id, "success" : "true"})

def update_row(table, json_dict):
    json_dict = {k : stringify(json_dict[k]) for k in json_dict}
    id = json_dict["id"]
    del json_dict["id"] # do not update the id
    db_update(db_conn, table, json_dict, id)
    return json.dumps({"success" : "true"})

@app.route('/massa/rootca/ca', methods = ['GET']) # not used
def get_rootca_ca():
    id = request.args.get('id')
    return get_row_by_attribute_as_json('ca', 'id', id)


###################### ENROLLMENT AUTHORITY ######################

@app.route('/massa/ea/registration', methods = ['GET'])
def get_ea_registration():
    attribute, value = get_first_attribute_value_pair_in_request(request)
    return get_row_by_attribute_as_json('registration', attribute, value)

@app.route('/massa/ea/ea', methods = ['GET'])
def get_ea_ea():
    attribute, value = get_first_attribute_value_pair_in_request(request)
    return get_row_by_attribute_as_json('ea', attribute, value)

@app.route('/massa/ea/enrolment', methods = ['POST', 'PUT', 'GET'])
def post_ea_enrollment():
    if request.method == 'POST':
        return insert_row('enrollment', request.get_json())
    elif request.method == 'PUT':
        update_row('enrollment', request.get_json())
        return '{"success" : "true"}'
    elif request.method == 'GET':
        attribute, value = get_first_attribute_value_pair_in_request(request)
        return get_row_by_attribute_as_json('enrollment', attribute, value)


@app.route('/massa/update_ea_cert', methods= ['POST'])
def update_ea_cert():
    if request.method == 'POST':
        cert = request.files['file']
        encoded_cert = base64.b64encode(cert.read())
        json_dict = {'id' : 7, 'certificate' : encoded_cert.decode("utf-8")}
        update_row('ea', json_dict)
    
    return '\nEA cert insertion OK'
        

###################### AUTHORIZATION AUTHORITY ######################

@app.route('/massa/aa/authorization_requests', methods = ['POST', 'PUT'])
def post_ea_authorization():
    if request.method == 'POST':
        return insert_row('authorizations_requests', request.get_json())
    elif request.method == 'PUT':
        update_row('authorizations_requests', request.get_json())
        return '{"success" : "true"}'


@app.route('/massa/aa/aa', methods = ['GET'])
def get_aa_aa():
    attribute, value = get_first_attribute_value_pair_in_request(request)
    return get_row_by_attribute_as_json('aa', attribute, value)

@app.route('/massa/update_aa_cert', methods= ['POST'])
def update_aa_cert():
    if request.method == 'POST':
        cert = request.files['file']
        encoded_cert = base64.b64encode(cert.read())
        json_dict = {'id' : 5, 'certificate' : encoded_cert.decode("utf-8")}
        update_row('aa', json_dict)
    
    return '\nEA cert insertion OK'

if __name__ == '__main__':
   db_create(db_conn)
   app.run(host='0.0.0.0', port=80)