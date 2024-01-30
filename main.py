import os
import boto3
import certifi
from flask import Flask, jsonify, request, make_response, render_template, flash, redirect, g, after_this_request
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import NoCredentialsError
from bson import ObjectId
from flask_basicauth import BasicAuth
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
jwt = JWTManager(app)
cors = CORS(app)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()
app.config["CORS_HEADERS"] = "Content-Type"

# mongo_db_url = os.environ.get("MONGO_DB_CONN_STRING")
# client = MongoClient(mongo_db_url)

# connection_string = f"mongodb://localhost:27017/wildcabarets"
# client = MongoClient(connection_string)

# app.config['MONGO_URI'] = "mongodb://localhost:27017/wildcabarets"
# mongo = PyMongo(app)
# mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabarets?tls=true&authSource=admin&replicaSet=superminds-cluster

connection_string = f"mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabaret?tls=true&authSource=admin&replicaSet=superminds-cluster" 
client = MongoClient(connection_string, tlsCAFile=certifi.where())
app.config['MONGO_URI'] = "mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabaret?tls=true&authSource=admin&replicaSet=superminds-cluster"
mongo = PyMongo(app)

# client = MongoClient('mongodb://localhost:27017/')
db = client['wildcabaret']
collection = db['users'] 
collection1 = db['booking']
collection2 = db['contact']
collection3 = db['event']
collection4 = db['newsletter']
files_collection = db['files']

auth = HTTPBasicAuth()
basic_auth = BasicAuth(app)
api = Api(app)

# def authenticate(username, password, required_scopes=None):
#     return users.get(username) == password

# Configure SWAGGER
SWAGGER_URL = '/swagger'  
API_URL = '/static/swagger.json'  # Our API url (can of course be a local resource)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  
    API_URL,
    config={ 
        'app_name': "Booking",
        'uiversion': 3,
        'supportedSubmitMethods': ['get', 'post', 'put', 'delete'],
        'securityDefinitions': {
            'basicAuth': {
                'type': 'basic',
                'description': 'Basic HTTP Authentication',
            },
        },
        'security': [{'basicAuth': []}],
    },
)

app.register_blueprint(swaggerui_blueprint, url_prefix = SWAGGER_URL)

@app.route('/static/swagger.json')
@auth.login_required
def send_swagger_json():
    return app.send_static_file('swagger.json')

# Configure JWT
app.config['JWT_SECRET_KEY'] = '854d9f0a3a754b16a6e1f3655b3cfbb5'
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwMTM2MTQwMCwianRpIjoiZGJlZmY2NzAtM2IzMi00NGQ3LTlkNzItMjY2NjliNjA3OGM0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InVzZXIxIiwibmJmIjoxNzAxMzYxNDAwLCJleHAiOjE3MDEzNjIzMDB9.Il6UB4Til2jOXTTaMhaFe0SOlhKmNkBQn6S3bdKzRtE'}

# Mock user data for demonstration
# users = {
#     'user1': {'password': 'password1'},
#     "admin": generate_password_hash("admin"),
# }

@auth.verify_password
def verify_password(username, password):
    print(f"Received username: {username}, password: {password}")
    user = mongo.db.users.find_one({'username': username})
    if user and bcrypt.check_password_hash(user['password'], password):
        return username
    if user:
        stored_password = user.get('password')
        print(f"Stored password: {stored_password}")
        if bcrypt.check_password_hash(stored_password, password):
            print("Authentication successful")
            return username

    print("Authentication failed")
    return False

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']

    existing_user = mongo.db.users.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    mongo.db.users.insert_one({
        'username': username,
        'password': hashed_password
    })

    return jsonify({'message': 'User registered successfully'}), 201

# Token creation route (login)
@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)

    user = mongo.db.users.find_one({'username': username})

    if user and user['password'] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# # Token creation route (login)
# @app.route('/login', methods=['GET','POST'])
# def login():
#     username = request.json.get('username', None)
#     password = request.json.get('password', None)

#     if username in users and users[username]['password'] == password:
#         access_token = create_access_token(identity=username)
#         return jsonify(access_token=access_token), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

# @auth.verify_password
# def verify_password(username, password):
#     if username in users and \
#             check_password_hash(users.get(username), password):
#         return username

@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.current_user())

apis = [
    "http://localhost:8080/book_now",
    "http://localhost:8080/contacts",
    "http://localhost:8080/events",
    "http://localhost:8080/newsletters"
    # Add more endpoints as needed
]

@app.route('/getAllData', methods=['GET'])
def get_aggregated_data():
    # aggregated_data = []
    # for api in apis:
    #         response = requests.get(api)
    #         data = response.json()
    #         aggregated_data.append(data)

    # return jsonify(aggregated_data)
    
    aggregated_data = {}
    
    # Get a list of all collection names in the database
    collections = db.list_collection_names()

    for collection_name in collections:
        # Retrieve all documents from the current collection
        collection_data = list(db[collection_name].find())
          # Convert ObjectId to string in each document
        for entry in collection_data:
            entry['_id'] = str(entry['_id'])
        aggregated_data[collection_name] = collection_data

    return jsonify(aggregated_data)

validation_rules = {
    "contactEmail": "required",
    "contactNumber": "required",
    "dietaryRequirements": "required",
    "message": "optional",
    "name": "required",
    "numberOfGuests": "required",
    "showDate": "required"
    }

# Create a booking
@app.route('/book_now', methods=['POST'])
def create_booking():
    # Assuming you receive JSON data in the request
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection1.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "contactEmail": data.get("contactEmail"),
        "contactNumber": data.get("contactNumber"),
        "dietaryRequirements": data.get("dietaryRequirements"),
        "message": data.get("message"),
        "name": data.get("name"),
        "numberOfGuests": data.get("numberOfGuests"),
        "showDate": data.get("showDate"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    # Send the response in JSON format
    return jsonify(response_data)

def validate_data(data, validation_rules):
    errors = []

    for field, rule in validation_rules.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a booking
@app.route('/book_now/<id>', methods=['PUT'])
@jwt_required()
def update_booking(id):
    # _json = request.json
    # _id = id
    # _name = _json['name']
    # _contactNumber = _json['contactNumber']
    # _contactEmail = _json['contactEmail']
    # _showDate = _json['showDate']
    # _numberOfGuests = _json['numberOfGuests']
    # _dietaryRequirements = _json['dietaryRequirements']
    # _message = _json['message']

    # if _name and _contactNumber and _contactEmail and _showDate and _numberOfGuests and _dietaryRequirements and _message and request.method == 'PUT':
    #     mongo.db.booking.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'name': _name, 'contactNumber': _contactNumber, 'contactEmail': _contactEmail, 'showDate': _showDate, 'numberOfGuests': _numberOfGuests, 'dietaryRequirements': _dietaryRequirements, 'message':  _message }})
    #     resp = jsonify("Booking Updated Successfully")
    #     resp.status_code = 200
    #     return resp
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = collection1.find_one({"_id": id})

    # print("Updating document with ID:", id)

    if existing_document is None:
        return jsonify({"error": "Document not found"}), 404

    result = collection1.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "contactEmail": data.get("contactEmail"),
        "contactNumber": data.get("contactNumber"),
        "dietaryRequirements": data.get("dietaryRequirements"),
        "message": data.get("message"),
        "name": data.get("name"),
        "numberOfGuests": data.get("numberOfGuests"),
        "showDate": data.get("showDate"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Document not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Document not updated"}), 404
    else:
        return jsonify(response_data)

# Get all books
@app.route('/book_now', methods=['GET'])
@jwt_required()
def get_bookings():
    # bookings = mongo.db.booking.find()
    # data = []
    # for booking in bookings:
    #     booking['_id'] = str(booking['_id']) 
    #     data.append(booking)
    # return jsonify(data)
    bookings = list(collection1.find())
    data = []
    for booking in bookings:
        booking['_id'] = str(booking['_id']) 
        data.append(booking)
    return jsonify(data)    
# Get a specific booking by ID
@app.route('/book_now/<id>', methods=['GET'])
@jwt_required()
def booking(id):
    booking = collection1.find_one({'_id':ObjectId(id)})
    if booking:
        booking["_id"] = str(booking["_id"])
        return booking
    else:
        return jsonify({"error": "Booking Not Found"}), 404
    # resp = dumps(booking)
    # return resp

# Delete a booking
@app.route('/book_now/<id>', methods=['DELETE'])
@jwt_required()
def delete_booking(id):
    # mongo.db.booking.delete_one({'_id':ObjectId(id)})
    # resp = jsonify("Booking Deleted Successfully")
    # resp.status_code = 200
    # return resp
    id = ObjectId(id)
    result = collection1.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Booking deleted successfully"})
    else:
        return jsonify({"error": "Booking not found or not deleted"}), 404

    # _json = request.json
    # _name = _json['name']
    # _contactNumber = _json['contactNumber']
    # _contactEmail = _json['contactEmail']
    # _showDate = _json['showDate']
    # _numberOfGuests = _json['numberOfGuests']
    # _dietaryRequirements = _json['dietaryRequirements']
    # _message = _json['message']

    # if _name and _contactNumber and _contactEmail and _showDate and _numberOfGuests and _dietaryRequirements and _message and request.method == 'POST':
    #     id = mongo.db.booking.insert_one({'name': _name, 'contactNumber': _contactNumber, 'contactEmail': _contactEmail, 'showDate': _showDate, 'numberOfGuests': _numberOfGuests, 'dietaryRequirements': _dietaryRequirements, 'message':  _message })
    #     return {"data":"Booking Added Successfully"}
    # else:
    #     return {'error':'Booking Not Found'}


# wildcabarets = client.wildcabarets
# booking_collection= wildcabarets.booking_collection

# bookings = [
#     {
#         'id': 1,
#         'Name':'Fabio',
#         'ContactNumber': 9999988888,
#         'ContactEmail': 'fabio@superminds.dev',
#         'ShowDate': '02.02.2024',
#         'NumberOfGuests': '10',
#         'DietaryRequirements': '5',
#         'Message': 'BlessUs'
#     }
# ]

# # Create a booking
# @app.route('/bookings', methods=['POST'])
# def create_booking():
#     # new_booking={'id':len(book_now)+1, 'Name':request.json['Name'], 'ContactNumber':request.json['ContactNumber'], 'ContactEmail': request.json['ContactEmail'], 'ShowDate': request.json['ShowDate'], 'NumberOfGuests': request.json['NumberOfGuests'], 'DietaryRequirements': request.json['DietaryRequirements'], 'Message': request.json['Message'] }
#     # book_now.append(new_booking)
#     # return new_booking

# # Update a booking
# @app.route('/bookings/<int:book_id>', methods=['PUT'])
# def update_booking(book_id):
#     for booking in bookings:
#         if booking['id']==book_id:
#             booking['Name']=request.json['Name']
#             booking['ContactNumber']=request.json['ContactNumber']
#             booking['ContactEmail']=request.json['ContactEmail']
#             booking['ShowDate']=request.json['ShowDate']
#             booking['NumberOfGuests']=request.json['NumberOfGuests']
#             booking['DietaryRequirements']=request.json['DietaryRequirements']
#             booking['Message']=request.json['Message']
#             return booking 
#     return {'error':'Booking not found'}

# # Get all books
# @app.route('/bookings', methods=['GET'])
# def get_bookings():
#     return bookings

# # Get a specific booking by ID
# @app.route('/book_now/<int:book_id>', methods=['GET'])
# def get_booking(book_id):
#     for booking in book_now:
#         if booking['id']==book_id:
#             return booking

#     return {'error':'Booking not found'}

# # Delete a booking
# @app.route('/bookings/<int:book_id>', methods=['DELETE'])
# def delete_booking(book_id):
#     for booking in bookings:
#         if booking['id']==book_id:
#             bookings.remove(booking)
#             return {"data":"Booking Deleted Successfully"}

#     return {'error':'Booking Not Found'}

# # Create a booking
# @app.route('/book_now', methods=['POST'])
# def create_booking():
#     Names = ["Pratyush", "Rahul"]
#     ContactNumbers = ["9667279794", "8860600257"]
#     ContactEmails = ["pratyush@superminds.dev", "rahul@superminds.dev"]
#     Showdates = ["01.01.2020", "09.09.2023"]
#     NumberOfGuests = ["4", "7"]
#     DietaryRequirements = ["100", "20"]
#     Messages = ["Bless", "F"]

#     bookings = []

#     for Name, ContactNumber, ContactEmail, Showdate, NumberOfGuest, DietaryRequirement, Message  in zip(Names, ContactNumbers, ContactEmails, Showdates, NumberOfGuests, DietaryRequirements, Messages ):
#         booking ={"Name": Name, "ContactNumber": ContactNumber, "ContactEmail": ContactEmail, "Showdate": Showdate, "NumberOfGuest": NumberOfGuest, "DietaryRequirement": DietaryRequirement, "Message": Message}
#         bookings.append(booking)
        
#     booking_collection.insert_many(bookings)
#     return {'data':'Booking Created Successfully'}

# Create a contact
@app.route('/contacts', methods=['POST'])
def create_contact():
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection2.insert_one(data).inserted_id

    response_data = {
        "contactEmail": data.get("contactEmail"),
        "contactNumber": data.get("contactNumber"),
        "dietaryRequirements": data.get("dietaryRequirements"),
        "message": data.get("message"),
        "name": data.get("name"),
        "numberOfGuests": data.get("numberOfGuests"),
        "showDate": data.get("showDate"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules):
    errors = []

    for field, rule in validation_rules.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a contact
@app.route('/contact/<id>', methods=['PUT'])
@jwt_required()
def update_contact(id):
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = collection2.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Contact not found"}), 404

    result = collection2.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "contactEmail": data.get("contactEmail"),
        "contactNumber": data.get("contactNumber"),
        "dietaryRequirements": data.get("dietaryRequirements"),
        "message": data.get("message"),
        "name": data.get("name"),
        "numberOfGuests": data.get("numberOfGuests"),
        "showDate": data.get("showDate"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Contact not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Contact not updated"}), 404
    else:
        return jsonify(response_data)

    # _json = request.json
    # _id = id
    # _name = _json['name']
    # _contactNumber = _json['contactNumber']
    # _contactEmail = _json['contactEmail']
    # _showDate = _json['showDate']
    # _numberOfGuests = _json['numberOfGuests']
    # _dietaryRequirements = _json['dietaryRequirements']
    # _message = _json['message']

    # if _name and _contactNumber and _contactEmail and _showDate and _numberOfGuests and _dietaryRequirements and _message and request.method == 'PUT':
    #     mongo.db.contact.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'name': _name, 'contactNumber': _contactNumber, 'contactEmail': _contactEmail, 'showDate': _showDate, 'numberOfGuests': _numberOfGuests, 'dietaryRequirements': _dietaryRequirements, 'message':  _message }})
    #     resp = jsonify("Contact Updated Successfully")
    #     resp.status_code = 200
    #     return resp

# Get all contacts
@app.route('/contacts', methods=['GET'])
@jwt_required()
def get_contacts():
    contacts = list(collection2.find())
    data = []
    for contact in contacts:
        contact['_id'] = str(contact['_id']) 
        data.append(contact)
    return jsonify(data)
    # contacts = mongo.db.contact.find()
    # data = []
    # for contact in contacts:
    #     contact['_id'] = str(contact['_id']) # This does the trick!
    #     data.append(contact)
    # return jsonify(data)

# Get a specific contact by ID
@app.route('/contact/<id>')
@jwt_required()
def contact(id):
    contact = collection2.find_one({'_id':ObjectId(id)})
    if contact:
        contact["_id"] = str(contact["_id"])
        return contact
    else:
        return jsonify({"error": "Contact Not Found"}), 404
    # contact = mongo.db.contact.find_one({'_id':ObjectId(id)})
    # if contact:
    #     contact["_id"] = str(contact["_id"])
    #     return contact
    # resp = dumps(contact)
    # return resp

# Delete a contact
@app.route('/contact/<id>', methods=['DELETE'])
@jwt_required()
def delete_contact(id):
    id = ObjectId(id)
    result = collection2.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Contact deleted successfully"})
    else:
        return jsonify({"error": "Contact not found or not deleted"}), 404
    # mongo.db.contact.delete_one({'_id':ObjectId(id)})
    # resp = jsonify("Contact Deleted Successfully")
    # resp.status_code = 200
    # return resp


    # args = parser.parse_args()

    # # Access the validated payload
    # name = args['name']
    # contactNumber = args['contactNumber']
    # contactEmail = args['contactEmail']
    # showDate = args['showDate']
    # numberOfGuests = args['numberOfGuests']
    # dietaryRequirements = args['dietaryRequirements']
    # message = args['message']

    # _json = request.json
    # _name = _json['name']
    # _contactNumber = _json['contactNumber']
    # _contactEmail = _json['contactEmail']
    # _showDate = _json['showDate']
    # _numberOfGuests = _json['numberOfGuests']
    # _dietaryRequirements = _json['dietaryRequirements']
    # _message = _json['message']

    # if _name and _contactNumber and _contactEmail and _showDate and _numberOfGuests and _dietaryRequirements and _message and request.method == 'POST':
    #     id = mongo.db.contact.insert_one({'name': _name, 'contactNumber': _contactNumber, 'contactEmail': _contactEmail, 'showDate': _showDate, 'numberOfGuests': _numberOfGuests, 'dietaryRequirements': _dietaryRequirements, 'message':  _message })
    #     return {"data":"Contact Added Successfully"}
    # else:
    #     return {'error':'Contact Not Found'}


# contact_us = [
#     {
#         'id': 1,
#         'Name':'Fabio',
#         'ContactNumber': 9999988888,
#         'ContactEmail': 'fabio@superminds.dev',
#         'ShowDate': '02.02.2024',
#         'NumberOfGuests': '10',
#         'DietaryRequirements': '5',
#         'Message': 'BlessUs'
#     }
# ]

# # Get all contacts
# @app.route('/contact_us', methods=['GET'])
# def get_contact_us():
#     return contact_us


# # Get a specific contact by ID
# @app.route('/contact_us/<int:contactid>', methods=['GET'])
# def get_contact(contactid):
#     for contact in contact_us:
#         if contact['id']==contactid:
#             return contact

#     return {'error':'Contact not found'}

# # Create a contact
# @app.route('/contact_us', methods=['POST'])
# def create_contact():
#     new_contact={'id':len(contact_us)+1, 'Name':request.json['Name'], 'ContactNumber':request.json['ContactNumber'], 'ContactEmail': request.json['ContactEmail'], 'ShowDate': request.json['ShowDate'], 'NumberOfGuests': request.json['NumberOfGuests'], 'DietaryRequirements': request.json['DietaryRequirements'], 'Message': request.json['Message'] }
#     contact_us.append(new_contact)
#     return new_contact


# # Update a contact
# @app.route('/contact_us/<int:contactid>', methods=['PUT'])
# def update_contact(contactid):
#     for contact in contact_us:
#         if contact['id']==contactid:
#             contact['Name']=request.json['Name']
#             contact['ContactNumber']=request.json['ContactNumber']
#             contact['ContactEmail']=request.json['ContactEmail']
#             contact['ShowDate']=request.json['ShowDate']
#             contact['NumberOfGuests']=request.json['NumberOfGuests']
#             contact['DietaryRequirements']=request.json['DietaryRequirements']
#             contact['Message']=request.json['Message']
#             return contact 
#     return {'error':'Contact not found'}

# # Delete a contact
# @app.route('/contact_us/<int:contactid>', methods=['DELETE'])
# def delete_contact(contactid):
#     for contact in contact_us:
#         if contact['id']==contactid:
#             contact_us.remove(contact)
#             return {"data":"Contact Deleted Successfully"}


#     return {'error':'Contact not found'}

validation_rules3 = {
    "amount": "required",
    "childAmount": "required",
    "date": "required",
    "deposit": "optional",
    "description": "required",
    "imageURL": "required",
    "meals": "required",
    "reservationsStartAt": "required",
    "reservationsEndsAt": "required",
    "showStarts": "required",
    "status": "required",
    "title": "required"
    }

# Create an event
@app.route('/events', methods=['POST'])
@jwt_required()
def create_event():
    # Assuming you receive JSON data in the request
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules3)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection3.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "amount": data.get("amount"),
        "childAmount": data.get("childAmount"),
        "date": data.get("date"),
        "deposit": data.get("deposit"),
        "description": data.get("description"),
        "imageURL": data.get("imageURL"),
        "meals": data.get("meals"),
        "reservationsStartAt": data.get("reservationsStartAt"),
        "reservationsEndsAt": data.get("reservationsEndsAt"),
        "showStarts": data.get("showStarts"),
        "status": data.get("status"),
        "title": data.get("title"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    # Send the response in JSON format
    return jsonify(response_data)

def validate_data(data, validation_rules3):
    errors = []

    for field, rule in validation_rules3.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors


    # _json = request.json
    # _amount = _json['amount']
    # _childAmount = _json['childAmount']
    # _date = _json['date']
    # _deposit = _json['deposit']
    # _description = _json['description']
    # _imageURL = _json['imageURL']
    # _meals = _json['meals']
    # _reservationsStartAt = _json['reservationsStartAt']
    # _reservationsEndsAt = _json['reservationsEndsAt']
    # _showStarts = _json['showStarts']
    # _status = _json['status']
    # _title = _json['title']

    # if _amount and _childAmount and _date and _deposit and _description and _imageURL and _meals and _reservationsStartAt and _reservationsEndsAt and _showStarts and _status and _title and request.method == 'POST':
    #     id = mongo.db.event.insert_one({'amount': _amount, 'childAmount': _childAmount, 'date': _date, 'deposit': _deposit, 'description': _description, 'imageURL': _imageURL, 'meals':  _meals, 'reservationsStartAt': _reservationsStartAt, 'reservationsEndsAt': _reservationsEndsAt, 'showStarts': _showStarts, 'status': _status, 'title': _title })
    #     return {"data":"Event Added Successfully"}
    # else:
    #     return {'error':'Event Not Found'}

# Update a event
@app.route('/event/<id>', methods=['PUT'])
@jwt_required()
def update_event(id):
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules3)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = collection3.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Event not found"}), 404

    result = collection3.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "amount": data.get("amount"),
        "childAmount": data.get("childAmount"),
        "date": data.get("date"),
        "deposit": data.get("deposit"),
        "description": data.get("description"),
        "imageURL": data.get("imageURL"),
        "meals": data.get("meals"),
        "reservationsStartAt": data.get("reservationsStartAt"),
        "reservationsEndsAt": data.get("reservationsEndsAt"),
        "showStarts": data.get("showStarts"),
        "status": data.get("status"),
        "title": data.get("title"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Event not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Event not updated"}), 404
    else:
        return jsonify(response_data)

    # _json = request.json
    # _id = id
    # _amount = _json['amount']
    # _childAmount = _json['childAmount']
    # _date = _json['date']
    # _deposit = _json['deposit']
    # _description = _json['description']
    # _imageURL = _json['imageURL']
    # _meals = _json['meals']
    # _reservationsStartAt = _json['reservationsStartAt']
    # _reservationsEndsAt = _json['reservationsEndsAt']
    # _showStarts = _json['showStarts']
    # _status = _json['status']
    # _title = _json['title']

    # if _amount and _childAmount and _date and _deposit and _description and _imageURL and _meals and _reservationsStartAt and _reservationsEndsAt and _showStarts and _status and _title and request.method == 'PUT':
    #     mongo.db.event.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'amount': _amount, 'childAmount': _childAmount, 'date': _date, 'deposit': _deposit, 'description': _description, 'imageURL': _imageURL, 'meals':  _meals, 'reservationsStartAt': _reservationsStartAt, 'reservationsEndsAt': _reservationsEndsAt, 'showStarts': _showStarts, 'status': _status, 'title': _title }})
    #     resp = jsonify("Event Updated Successfully")
    #     resp.status_code = 200
    #     return resp

# Get all events
@app.route('/events', methods=['GET'])
def get_events():
    events = list(collection3.find())
    data = []
    for event in events:
            event['_id'] = str(event['_id']) 
            data.append(event)
    return jsonify(data)
    # events = mongo.db.event.find()
    # data = []
    # for event in events:
    #     event['_id'] = str(event['_id']) # This does the trick!
    #     data.append(event)
    # return jsonify(data)

# Get a specific event by ID
@app.route('/event/<id>')
@jwt_required()
def event(id):
    event = collection3.find_one({'_id':ObjectId(id)})
    if event:
        event["_id"] = str(event["_id"])
        return event
    else:
        return jsonify({"error": "Event Not Found"}), 404
    # event = mongo.db.event.find_one({'_id':ObjectId(id)})
    # if event:
    #     event["_id"] = str(event["_id"])
    #     return event
    # resp = dumps(event)
    # return resp

# Delete a event
@app.route('/event/<id>', methods=['DELETE'])
@jwt_required()
def delete_event(id):
    id = ObjectId(id)
    result = collection3.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Event deleted successfully"})
    else:
        return jsonify({"error": "Event not found or not deleted"}), 404
    # mongo.db.event.delete_one({'_id':ObjectId(id)})
    # resp = jsonify("Event Deleted Successfully")
    # resp.status_code = 200
    # return resp

# events = [
#     {
#         'id': 1,
#         'amount': 100,
#         'childAmount': 100,
#         'date': '02.02.2024',
#         'deposit': 9999988888,
#         'description': 'Nice event',
#         'imageURL':'www.xyz.com',
#         'meals': '10',
#         'reservationsStartAt': '5',
#         'reservationsEndsAt': '9',
#         'showStarts' : '4',
#         'status' : 'cancelled',
#         'title': 'event'
#     }
# ]

# # Get all events
# @app.route('/events', methods=['GET'])
# def get_events():
#     return events


# # Get a specific event by ID
# @app.route('/events/<int:eventid>', methods=['GET'])
# def get_event(eventid):
#     for event in events:
#         if event['id']==eventid:
#             return event

#     return {'error':'Event not found'}

# # Create an event
# @app.route('/events', methods=['POST'])
# def create_event():
#     new_event={'id':len(events)+1, 'amount':request.json['amount'], 'childAmount':request.json['childAmount'], 'date': request.json['date'], 'deposit': request.json['deposit'], 'description': request.json['description'], 'imageURL': request.json['imageURL'], 'meals': request.json['meals'], 'reservationsStartAt': request.json['reservationsStartAt'], 'reservationsEndsAt': request.json['reservationsEndsAt'],'showStarts': request.json['showStarts'], 'status': request.json['status'], 'title': request.json['title'] }
#     events.append(new_event)
#     return new_event


# UPLOAD_FOLDER = '/Users/pratyushsharma/booking'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE_BYTES = 500 * 500 #10 * 1024 * 1024
# DigitalOcean Spaces configurations
DO_SPACES_ENDPOINT = 'https://wild-cabarets.fra1.digitaloceanspaces.com'  # Replace with your Space URL
DO_ACCESS_KEY = 'DO00H8HLFYNACV6LJ3GP'  # Replace with your DigitalOcean Spaces access key
DO_SECRET_KEY = 'fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY'  # Replace with your DigitalOcean Spaces secret key
DO_BUCKET_NAME = 'wild-cabarets'  # Replace with your DigitalOcean Spaces bucket name

# # Create a connection to DigitalOcean Spaces
# s3 = boto3.client('s3', endpoint_url=DO_SPACES_ENDPOINT, aws_access_key_id=DO_ACCESS_KEY, aws_secret_access_key=DO_SECRET_KEY)

def allowed_file_size(file):
    return file.content_length <= MAX_FILE_SIZE_BYTES

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# # Create an event image
# @app.route('/events/<id>/image', methods=['POST'])
# @jwt_required()
# def upload_image(id):
#     try:
#         if 'file' not in request.files or 'id' not in request.form:
#             return jsonify({"error": "No file or event ID provided"}), 400

#         file = request.files['file']

#         if file.filename == '':
#             return jsonify({"error": "No selected file"}), 400

#         if not allowed_file_size(file):
#             return jsonify({"error": "File size exceeds the allowed limit"}), 400

#         device_type = request.form.get('device_type', 'unknown')

#        # Use the event ID to create a unique file name
#         file_name = f"{device_type}_{id}_{file.filename}"

#         # Upload the file to DigitalOcean Spaces
#         s3.upload_fileobj(file, DO_BUCKET_NAME, file_name)

#         # Get the public URL of the uploaded file
#         file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_name}"
#         # file_url = f"{file_name}"

#         return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})
#     except NoCredentialsError:
#         return jsonify({'error': 'Credentials not available. Check your DigitalOcean Spaces access key and secret key.'}), 500
    # except Exception as e:
    #     return jsonify({'error': str(e)}), 500

def upload_to_digitalocean(file, file_name, device_type, event_id):
    try:
        s3 = boto3.client('s3',
            aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
            aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        # Create a folder with the specified device type
        folder_path = f"{device_type}/"
        file_path = os.path.join(folder_path, file_name)

        # Upload the file to DigitalOcean Spaces
        s3.upload_fileobj(file, DO_BUCKET_NAME, file_path)

        # Get the public URL of the uploaded file
        file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

        file_info = {
            'filename': file_name,
            'device_type': device_type,
            'url': file_url,
            'event_id': event_id  # Assuming you have an 'id' variable available in your code
        }
        files_collection.insert_one(file_info)

        return file_url

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

@app.route('/events/<id>/image', methods=['POST', 'DELETE'])
@jwt_required()
def upload_and_delete_image(id):
    try:
        file_name = None

        s3 = boto3.client('s3',
            aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
            aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        if request.method == 'POST':
            # Check if the POST request has the file part
            if 'file' not in request.files or 'device_type' not in request.form:
                return jsonify({"error": "No file or device type provided"}), 400

            file = request.files['file']
            device_type = request.form['device_type']

            # If the user does not select a file, the browser submits an empty file without a filename
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400

            file_name = f"{file.filename}"

            # Upload the file to DigitalOcean Spaces and get the file URL
            file_url = upload_to_digitalocean(file, file_name, device_type, id)

            return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

        elif request.method == 'DELETE':

            file_name = request.json.get('filename') or request.args.get('filename')

            if file_name is None:
                return jsonify({"error": "No file specified for deletion"}), 400

            # Delete the file from DigitalOcean Spaces
            s3 = boto3.client('s3',
                aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
                aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
                endpoint_url=DO_SPACES_ENDPOINT
            )
            # filename = request.json.get('filename')  # Assuming you send the filename in the request body

            delete_file_from_digitalocean(file_name)

            s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

            files_collection.delete_one({'filename': file_name})

            return {'message': f'{file_name} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_from_digitalocean(file_name):
    try:
        s3 = boto3.client('s3',
            aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
            aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        # Delete the file from DigitalOcean Spaces
        s3.delete_object(Bucket=DO_BUCKET_NAME, Key=file_name)

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

def delete_file_from_mongodb(file_name):
    # Delete the file information from MongoDB
    files_collection.delete_one({'filename': file_name})

@app.route('/events/<id>/image/<filename>', methods=['DELETE'])
@jwt_required()
def delete_uploaded_image(id, filename):
    try:

        # file_name_in_digitalocean = f"{filename}"
        # Delete the file from DigitalOcean Spaces
        delete_file_from_digitalocean(filename)

        # Delete the file information from MongoDB
        delete_file_from_mongodb(filename)

        return {'message': f'File {filename} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500




# # Delete an event image <id>
# @app.route('/events/<string:file_name>/image', methods=['DELETE'])
# @jwt_required()
# def delete(file_name):
#         try:
#             # Delete the file from DigitalOcean Spaces
#             s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

#             return {'message': f'File {file_name} deleted successfully'}

#         except NoCredentialsError:
#             return {'error': 'Credentials not available'}

# # Update an event
# @app.route('/events/<int:eventid>', methods=['PUT'])
# def update_event(eventid):
#     for event in events:
#         if event['id']==eventid:
#             event['amount'] =request.json['amount'], 
#             event['childAmount']=request.json['childAmount'], 
#             event['date']= request.json['date'], 
#             event['deposit']= request.json['deposit'], 
#             event['description']= request.json['description'], 
#             event['imageURL']= request.json['imageURL'], 
#             event['meals']= request.json['meals'],
#             event['reservationsStartAt'] = request.json['reservationsStartAt'], 
#             event['reservationsEndsAt']= request.json['reservationsEndsAt'],
#             event['showStarts']= request.json['showStarts'],
#             event['status']= request.json['status'], 
#             event['title']= request.json['title']
#             return  
#     return {'error':'Event not found'}

# # Delete an event
# @app.route('/events/<int:eventid>', methods=['DELETE'])
# def delete_event(eventid):
#     for event in events:
#         if event['id']==eventid:
#             events.remove(event)
#             return {"data":"Event Deleted Successfully"}

#     return {'error':'Event not found'}

class SubscribeResource(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        email = data.get("email")

        if not email:
            return {"message": "Email is required"}, 400

        # Check if the email is already subscribed
        existing_subscriber = collection4.find_one({"email": email})

        if existing_subscriber:
            return {"message": "Email is already subscribed"}, 400

        # Add the new subscriber
        current_time = datetime.utcnow()
        new_subscriber = {"email": email, "subscribed": True, "created_at": current_time, "updated_at": current_time}
        collection4.insert_one(new_subscriber)

        return {"message": "Subscribed successfully"}, 201

        

        # response_data = {
        #     "email": data.get("email"),
        #     "_id": str(inserted_id)
        # # Add more fields as needed
        # }


        # return jsonify(response_data)


class UnsubscribeResource(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()

        email = data.get("email")

        if not email:
            return {"message": "Email is required"}, 400

        # Find the subscriber by email
        subscriber = collection4.find_one({"email": email})

        if not subscriber:
            return {"message": "Email is not subscribed"}, 404

        # Update the subscription status to False
        current_time = datetime.utcnow()
        collection4.update_one(
            {"email": email},
            {"$set": {"subscribed": False, "updated_at": current_time}}
        )

        return {"message": "Unsubscribed successfully"}, 200


class SubscribersListResource(Resource):
    @jwt_required()
    def get(self):
        # Retrieve all subscribers
        subscribers = list(collection4.find())
        data = []
        for subscriber in subscribers:
            subscriber['_id'] = str(subscriber['_id']) 
            data.append(subscriber)
        return jsonify(data)

# API routes
api.add_resource(SubscribeResource, "/newsletter-subscribe")
api.add_resource(UnsubscribeResource, "/unsubscribe")
api.add_resource(SubscribersListResource, "/subscribers")


# validation_rules4 = {
#     "email": "required"
#     }

# # Create a newsletter
# @app.route('/newsletters', methods=['POST'])
# def create_newsletter():
#     # Assuming you receive JSON data in the request
#     data = request.get_json()
#     # Perform your validations
#     validation_errors = validate_data(data, validation_rules4)

#     if validation_errors:
#         # If there are validation errors, send a response with the errors
#         return jsonify({"errors": validation_errors}), 400

#     inserted_id = collection4.insert_one(data).inserted_id

#     # If validation passes, create a response with the desired data
#     response_data = {
#         "email": data.get("email"),
#         "_id": str(inserted_id)
#         # Add more fields as needed
#     }

#     # Send the response in JSON format
#     return jsonify(response_data)

# def validate_data(data, validation_rules4):
#     errors = []

#     for field, rule in validation_rules4.items():
#         if rule == "required" and not data.get(field):
#             errors.append(f"{field} is required.")
#         elif rule == "optional" and field in data and not data.get(field):
#             errors.append(f"{field} must be optional.")

#     return errors

# # Update a newsletter
# @app.route('/newsletter/<id>', methods=['PUT'])
# @jwt_required()
# def update_newsletter(id):
#     id = ObjectId(id)
#     data = request.get_json()
#     validation_errors = validate_data(data, validation_rules4)

#     if validation_errors:
#         return jsonify({"errors": validation_errors}), 400
    
#     existing_document = collection4.find_one({"_id": id})

#     if existing_document is None:
#         return jsonify({"error": "Newsletter not found"}), 404

#     result = collection4.update_one({"_id": ObjectId(id)}, {"$set": data})

#     response_data = {
#         "email": data.get("email"),
#         "_id": str(id)
#         # Add more fields as needed
#     }

#     if result.matched_count == 0:
#         return jsonify({"error": "Newsletter not found"}), 404
#     elif result.modified_count == 0:
#         return jsonify({"error": "Newsletter not updated"}), 404
#     else:
#         return jsonify(response_data)

# # Get all newsletters
# @app.route('/newsletters', methods=['GET'])
# @jwt_required()
# def get_newsletters():
#     newsletters = list(collection4.find())
#     data = []
#     for newsletter in newsletters:
#         newsletter['_id'] = str(newsletter['_id']) 
#         data.append(newsletter)
#     return jsonify(data)

# # Get a specific newsletter by ID
# @app.route('/newsletter/<id>')
# @jwt_required()
# def newsletter(id):
#     newsletter = collection4.find_one({'_id':ObjectId(id)})
#     if newsletter:
#         newsletter["_id"] = str(newsletter["_id"])
#         return newsletter
#     else:
#         return jsonify({"error": "Newsletter Not Found"}), 404

# Delete a newsletter
@app.route('/newsletter/<id>', methods=['DELETE'])
@jwt_required()
def delete_newsletter(id):
    id = ObjectId(id)
    result = collection4.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Subscriber deleted successfully"})
    else:
        return jsonify({"error": "Subscriber not found or not deleted"}), 404

# Run the flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)