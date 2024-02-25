import os
import boto3
import certifi
import time
from flask import Flask, jsonify, request, make_response, render_template, flash, redirect, g, after_this_request, current_app
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
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

connection_string = f"mongodb://localhost:27017/wildcabaret"
client = MongoClient(connection_string, tlsCAFile=certifi.where())

app.config['MONGO_URI'] = "mongodb://localhost:27017/wildcabaret"
mongo = PyMongo(app)
# mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabarets?tls=true&authSource=admin&replicaSet=superminds-cluster

# connection_string = f"mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabaret?tls=true&authSource=admin&replicaSet=superminds-cluster" 
# client = MongoClient(connection_string, tlsCAFile=certifi.where())
# app.config['MONGO_URI'] = "mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/wildcabaret?tls=true&authSource=admin&replicaSet=superminds-cluster"
# mongo = PyMongo(app)

client = MongoClient('mongodb://localhost:27017/')
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
        'validatorUrl': None
    },
)

app.register_blueprint(swaggerui_blueprint, url_prefix = SWAGGER_URL)

@app.route('/static/swagger.json')
@basic_auth.required
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
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwMTM2MTQwMCwianRpIjoiZGJlZmY2NzAtM2IzMi00NGQ3LTlkNzItMjY2NjliNjA3OGM0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InVzZXIxIiwibmJmIjoxNzAxMzYxNDAwLCJleHAiOjE3MDEzNjIzMDB9.Il6UB4Til2jOXTTaMhaFe0SOlhKmNkBQn6S3bdKzRtE'
    }

# @auth.verify_password
# def verify_password(username, password):
#     print(f"Received username: {username}, password: {password}")
#     user = mongo.db.users.find_one({'username': username})
#     if user and bcrypt.check_password_hash(user['password'], password):
#         return username
#     if user:
#         stored_password = user.get('password')
#         print(f"Stored password: {stored_password}")
#         if bcrypt.check_password_hash(stored_password, password):
#             print("Authentication successful")
#             return username

#     print("Authentication failed")
#     return False

# @app.route('/register', methods=['POST'])
# def register_user():
#     data = request.get_json()

#     if 'username' not in data or 'password' not in data:
#         return jsonify({'error': 'Username and password are required'}), 400

#     username = data['username']
#     password = data['password']

#     existing_user = mongo.db.users.find_one({'username': username})
#     if existing_user:
#         return jsonify({'error': 'Username already exists'}), 409

#     hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#     mongo.db.users.insert_one({
#         'username': username,
#         'password': hashed_password
#     })

#     return jsonify({'message': 'User registered successfully'}), 201

# # Token creation route (login)
# @app.route('/login', methods=['GET','POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username', None)
#     password = data.get('password', None)

#     user = mongo.db.users.find_one({'username': username})

#     if user and user['password'] == password:
#         access_token = create_access_token(identity=username)
#         return jsonify(access_token=access_token), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

# JWT configuration
app.config['JWT_SECRET_KEY'] = '854d9f0a3a754b16a6e1f3655b3cfbb5'  # Change this to a secret key of your choice
jwt = JWTManager(app)

# Register endpoint
class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return {'message': 'Both username and password are required'}, 400
        if collection.find_one({'username': username}):
            return {'message': 'Username already exists'}, 400
        new_user = User(username, password)
        collection.insert_one({'username': new_user.username, 'password': new_user.password})
        return {'message': 'User registered successfully'}, 201

# Login endpoint
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = collection.find_one({'username': username})
        if not user or not check_password_hash(user['password'], password):
            return {'message': 'Invalid username or password'}, 401
        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt

blacklist = set()  # Set to store revoked tokens

@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_data):
    jti = jwt_data['jti']
    return jti in blacklist

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')

app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = 'password'
basic_auth = BasicAuth(app)

# Mock user data (for basic auth purposes)
USERS = {
    'user1': 'password1',
    'user2': 'password2',
    'admin': 'password'  # Admin credentials
}

# User model
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

class SecretResource(Resource):
    @basic_auth.required
    def get(self):
        return "Hello, {}!".format(auth.current_user())

api.add_resource(SecretResource, '/')

# @app.route('/')
# @auth.login_required
# def index():
#     return "Hello, {}!".format(auth.current_user())

validation_rules = {
    "contactEmail": "required",
    "contactNumber": "required",
    "dietaryRequirements": ["required", "in:Yes, No"],
    "message": "optional",
    "name": "required",
    "numberOfGuests": "required",
    "showDate": "required"
    }

# Create a booking
@app.route('/book-now', methods=['POST'])
def create_booking():
    # Assuming you receive JSON data in the request
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    # Validate date format
    try:
        datetime.strptime(data["showDate"], "%Y-%m-%d")
    except ValueError:
        return jsonify({"errors": ["Invalid date format. Date must be in YYYY-MM-DD format."]}), 400

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
        elif rule.startswith("in:"):
            values = rule.split(":")[1].split(",")
            if data.get(field) not in values:
                errors.append(f"{field} must be one of {', '.join(values)}.")
        elif rule == "number":
            if not isinstance(data.get(field), int):
                errors.append(f"{field} must be a number.")
        elif rule == "date":
            try:
                datetime.strptime(data.get(field), "%Y-%m-%d")
            except ValueError:
                errors.append(f"{field} must be in YYYY-MM-DD format.")

    return errors

# Update a booking
@app.route('/book-now/<id>', methods=['PUT'])
@jwt_required()
def update_booking(id):
    id = ObjectId(id)
    data = request.get_json()

    booking = collection1.find_one({'_id':ObjectId(id)})
    if booking is None:
        return jsonify({"error": "Booking not found"}), 404

    existing_data = {
        "contactEmail": booking.get("contactEmail"),
        "contactNumber": booking.get("contactNumber"),
        "dietaryRequirements": booking.get("dietaryRequirements"),
        "message": booking.get("message"),
        "name": booking.get("name"),
        "numberOfGuests": booking.get("numberOfGuests"),
        "showDate": booking.get("showDate"),
        # Add more fields as needed
    }

    data.pop('_id', None)
    # Merge existing data with new data
    merged_data = {**existing_data, **data}

    result = collection1.update_many({"_id": ObjectId(id)}, {"$set": merged_data})


    if result.matched_count == 0:
        return jsonify({"error": "Booking not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Booking not updated"}), 404
    else:
        return jsonify(merged_data)

# Get all books
@app.route('/book-now', methods=['GET'])
def get_bookings():
    bookings = list(collection1.find())
    data = []
    for booking in bookings:
        booking['_id'] = str(booking['_id']) 
        data.append(booking)
    return jsonify(data)    

# Get a specific booking by ID
@app.route('/book-now/<id>', methods=['GET'])
def booking(id):
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404  
    booking = collection1.find_one({'_id':ObjectId(id)})
    if booking:
        booking["_id"] = str(booking["_id"])
        return booking
    else:
        return jsonify({"error": "Booking Not Found"}), 404

# Delete a booking
@app.route('/book-now/<id>', methods=['DELETE'])
@jwt_required()
def delete_booking(id):
    # id = ObjectId(id)
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404  
    result = collection1.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Booking deleted successfully"})
    else:
        return jsonify({"error": "Booking not found or not deleted"}), 404

# Create a contact
@app.route('/contact-us', methods=['POST'])
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
@app.route('/contact-us/<id>', methods=['PUT'])
@jwt_required()
def update_contact(id):
    # id = ObjectId(id)
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404 

    data = request.get_json()
    existing_document = collection2.find_one({'_id':ObjectId(id)})

    if existing_document is None:
        return jsonify({"error": "Contact not found"}), 404

    response_data = {
        "contactEmail": existing_document.get("contactEmail"),
        "contactNumber": existing_document.get("contactNumber"),
        "dietaryRequirements": existing_document.get("dietaryRequirements"),
        "message": existing_document.get("message"),
        "name": existing_document.get("name"),
        "numberOfGuests": existing_document.get("numberOfGuests"),
        "showDate": existing_document.get("showDate")
        # Add more fields as needed
    }

    data.pop('_id', None)
    merged_data = {**response_data, **data}
    result = collection2.update_many({"_id": ObjectId(id)}, {"$set": merged_data})

    if result.matched_count == 0:
        return jsonify({"error": "Contact not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Contact not updated"}), 404
    else:
        return jsonify(merged_data)

# Get all contacts
@app.route('/contact-us', methods=['GET'])
def get_contacts():
    contacts = list(collection2.find())
    data = []
    for contact in contacts:
        contact['_id'] = str(contact['_id']) 
        data.append(contact)
    return jsonify(data)

# Get a specific contact by ID
@app.route('/contact-us/<id>')
def contact(id):
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404  

    contact = collection2.find_one({'_id':ObjectId(id)})
    if contact:
        contact["_id"] = str(contact["_id"])
        return contact
    else:
        return jsonify({"error": "Contact Not Found"}), 404

# Delete a contact
@app.route('/contact-us/<id>', methods=['DELETE'])
@jwt_required()
def delete_contact(id):
    # id = ObjectId(id)
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404  

    result = collection2.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Contact deleted successfully"})
    else:
        return jsonify({"error": "Contact not found or not deleted"}), 404

from datetime import datetime

validation_rules3 = {
    "amount": "required",
    "childAmount": "required",
    "date": "required",
    "deposit": "required",
    "description": "required",
    "meals": "required",
    "reservationsStartAt": "required",
    "reservationsEndsAt": "required",
    "showStarts": "required",
    "status": ["required", "in:book now,sold out,cancelled"],
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

    # Validate date format
    try:
        datetime.strptime(data["date"], "%Y-%m-%d")
    except ValueError:
        return jsonify({"errors": ["Invalid date format. Date must be in YYYY-MM-DD format."]}), 400

    inserted_id = collection3.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "amount": data.get("amount"),
        "childAmount": data.get("childAmount"),
        "date": data.get("date"),
        "deposit": data.get("deposit"),
        "description": data.get("description"),
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
    return jsonify(response_data), 201

def validate_data(data, validation_rules3):
    errors = []

    for field, rule in validation_rules3.items():
        if isinstance(rule, list):
            for r in rule:
                if r == "required" and not data.get(field):
                    errors.append(f"{field} is required.")
                elif r.startswith("in:"):
                    values = r.split(":")[1].split(",")
                    if data.get(field) not in values:
                        errors.append(f"{field} must be one of {', '.join(values)}.")
        else:
            if rule == "required" and not data.get(field):
                errors.append(f"{field} is required.")
            elif rule == "optional" and field in data and not data.get(field):
                errors.append(f"{field} must be optional.")

    return errors

# Update a event
@app.route('/events/<id>', methods=['PUT'])
@jwt_required()
def update_event(id):
    # id = ObjectId(id)

    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404  

    data = request.get_json()
    existing_document = collection3.find_one({'_id':ObjectId(id)})

    if existing_document is None:
        return jsonify({"error": "Event not found"}), 404

    response_data = {
        "amount": existing_document.get("amount"),
        "childAmount": existing_document.get("childAmount"),
        "date": existing_document.get("date"),
        "deposit": existing_document.get("deposit"),
        "description": existing_document.get("description"),
        "meals": existing_document.get("meals"),
        "reservationsStartAt": existing_document.get("reservationsStartAt"),
        "reservationsEndsAt": existing_document.get("reservationsEndsAt"),
        "showStarts": existing_document.get("showStarts"),
        "status": existing_document.get("status"),
        "title": existing_document.get("title")
    }

    data.pop('_id', None)
    merged_data = {**response_data, **data}
    result = collection3.update_many({"_id": ObjectId(id)}, {"$set": merged_data})

    if result.matched_count == 0:
        return jsonify({"error": "Event not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Event not updated"}), 404
    else:
        return jsonify(merged_data)

# Get all events
@app.route('/events', methods=['GET'])
def get_events():
    events = list(collection3.find())
    data = []
    for event in events:
            event['_id'] = str(event['_id']) 
            data.append(event)
    return jsonify(data)

# Get a specific event by ID
@app.route('/events/<id>')
def event(id):

    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404

    event = collection3.find_one({'_id':ObjectId(id)})
    if event:
        event["_id"] = str(event["_id"])
        return event
    else:
        return jsonify({"error": "Event Not Found"}), 404

# Delete a event
@app.route('/events/<id>', methods=['DELETE'])
@jwt_required()
def delete_event(id):
    # id = ObjectId(id)

    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404

    result = collection3.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Event deleted successfully"})
    else:
        return jsonify({"error": "Event not found or not deleted"}), 404

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
DO_SPACES_ENDPOINT = 'https://wild-cabarets.fra1.digitaloceanspaces.com'  # Replace with your Space URL
DO_ACCESS_KEY = 'DO00H8HLFYNACV6LJ3GP'  # Replace with your DigitalOcean Spaces access key
DO_SECRET_KEY = 'fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY'  # Replace with your DigitalOcean Spaces secret key
DO_BUCKET_NAME = 'wild-cabarets'  # Replace with your DigitalOcean Spaces bucket name

def allowed_file_size(file):
    return file.content_length <= MAX_FILE_SIZE_BYTES

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def upload_to_digitalocean(file, file_name, device_type, id):
#     try:
#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )
#         id = id.strip().replace(' ', '_')
#         file_name = file_name.strip().replace(' ', '_')

#         unique_filename = f"{id}_{file_name}"

#         folder_path = f"{device_type}/"
#         file_path = os.path.join(folder_path, unique_filename)

#         # Upload the file to DigitalOcean Spaces
#         s3.upload_fileobj(
#             file,
#             DO_BUCKET_NAME,
#             file_path,
#             ExtraArgs={'ACL': 'public-read'}  # Set ACL to public-read
#         )

#         # Get the public URL of the uploaded file
#         # file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"
#         # file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{folder_path}{id}_{file_name}"
#         file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

#         file_info = {
#             'filename': file_name,
#             'device_type': device_type,
#             'url': file_url,
#             'id': id  # Assuming you have an 'id' variable available in your code
#         }
#         files_collection.insert_one(file_info)

#         return file_url

#     except NoCredentialsError:
#         raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
#     except Exception as e:
#         raise Exception(str(e))

# @app.route('/events/image', methods=['POST', 'DELETE'])
# # @jwt_required()
# def upload_and_delete_image(id):
#     try:
#         file_name = None

#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         if request.method == 'POST':
#             # Check if the POST request has the file part
#             if 'file' not in request.files or 'device_type' not in request.form:
#                 return jsonify({"error": "No file or device type provided"}), 400

#             file = request.files['file']
#             device_type = request.form['device_type']

#             # If the user does not select a file, the browser submits an empty file without a filename
#             if file.filename == '':
#                 return jsonify({"error": "No selected file"}), 400

#             file_name = f"{file.filename}"

#             # Upload the file to DigitalOcean Spaces and get the file URL
#             file_url = upload_to_digitalocean(file, file_name, device_type, id)

#             return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

#         elif request.method == 'DELETE':

#             file_name = request.json.get('filename') or request.args.get('filename')

#             if file_name is None:
#                 return jsonify({"error": "No file specified for deletion"}), 400

#             # Delete the file from DigitalOcean Spaces
#             s3 = boto3.client('s3',
#                 aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#                 aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#                 endpoint_url=DO_SPACES_ENDPOINT
#             )
#             # filename = request.json.get('filename')  # Assuming you send the filename in the request body

#             delete_file_from_digitalocean(file_name)

#             s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

#             files_collection.delete_one({'filename': file_name})

#             return {'message': f'{file_name} deleted successfully'}

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# def upload_to_digitalocean(file, file_name, device_type):
#     try:
#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         file_name = file_name.strip().replace(' ', '_')

#         # Generate a timestamp
#         timestamp = int(time.time())

#         unique_filename = f"{timestamp}_{file_name}"

#         folder_path = f"{device_type}/"
#         file_path = os.path.join(folder_path, unique_filename)

#         # Upload the file to DigitalOcean Spaces
#         s3.upload_fileobj(
#             file,
#             DO_BUCKET_NAME,
#             file_path,
#             ExtraArgs={'ACL': 'public-read'}  # Set ACL to public-read
#         )

#         # Get the public URL of the uploaded file
#         file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

#         file_info = {
#             'filename': file_name,
#             'device_type': device_type,
#             'url': file_url,
#             'timestamp': timestamp
#         }
#         files_collection.insert_one(file_info)

#         return file_url

#     except NoCredentialsError:
#         raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
#     except Exception as e:
#         raise Exception(str(e))

from urllib.parse import quote

def upload_to_digitalocean(file, file_name, device_type, id):
    try:
        s3 = boto3.client('s3',
        aws_access_key_id=DO_ACCESS_KEY,
        aws_secret_access_key=DO_SECRET_KEY,
        endpoint_url=DO_SPACES_ENDPOINT
        )

        # Replace spaces in the file name with underscores
        file_name = file_name.strip().replace(' ', '_')

        # URL-encode the file name
        encoded_file_name = quote(file_name, safe='')

        unique_filename = f"{encoded_file_name}"

        folder_path = f"{device_type}/{id}/"  # Include the id in the folder path
        # file_path = os.path.join(folder_path, file_name)
        file_path = os.path.join(folder_path, unique_filename)



        # Upload the file to DigitalOcean Spaces
        s3.upload_fileobj(
            file,
            DO_BUCKET_NAME,
            file_path,
            ExtraArgs={'ACL': 'public-read'}  # Set ACL to public-read
        )

        # Get the public URL of the uploaded file
        file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{folder_path}{file_name}"

        file_info = {
            'filename': file_name,
            'device_type': device_type,
            'url': file_url,
            'id': id
        }
        files_collection.insert_one(file_info)

        return file_url

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

# @app.route('/events/image', methods=['POST', 'DELETE'])
# # @jwt_required()
# def upload_and_delete_image():
#     try:
#         file_name = None

#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         if request.method == 'POST':
#             # Check if the POST request has the file part
#             if 'file' not in request.files or 'device_type' not in request.form:
#                 return jsonify({"error": "No file or device type provided"}), 400

#             file = request.files['file']
#             device_type = request.form['device_type']

#             # If the user does not select a file, the browser submits an empty file without a filename
#             if file.filename == '':
#                 return jsonify({"error": "No selected file"}), 400

#             file_name = f"{file.filename}"

#             # Upload the file to DigitalOcean Spaces and get the file URL
#             file_url = upload_to_digitalocean(file, file_name, device_type)

#             return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

#         elif request.method == 'DELETE':

#             file_name = request.json.get('filename') or request.args.get('filename')

#             if file_name is None:
#                 return jsonify({"error": "No file specified for deletion"}), 400

#             # Delete the file from DigitalOcean Spaces
#             s3 = boto3.client('s3',
#                 aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#                 aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#                 endpoint_url=DO_SPACES_ENDPOINT
#             )
#             # filename = request.json.get('filename')  # Assuming you send the filename in the request body

#             delete_file_from_digitalocean(file_name)

#             s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

#             files_collection.delete_one({'filename': file_name})

#             return {'message': f'{file_name} deleted successfully'}

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

@app.route('/events/image', methods=['POST', 'DELETE'])
@jwt_required()
def upload_and_delete_image():
    try:
        file_name = None

        s3 = boto3.client('s3',
        aws_access_key_id=DO_ACCESS_KEY,
        aws_secret_access_key=DO_SECRET_KEY,
        endpoint_url=DO_SPACES_ENDPOINT
        )

        if request.method == 'POST':
            # Check if the POST request has the file part
            if 'file' not in request.files or 'device_type' not in request.form or 'id' not in request.form:
                return jsonify({"error": "No file, device type, or id provided"}), 400

            file = request.files['file']
            device_type = request.form['device_type']
            id = request.form['id']  # Add this line to get the id from the request form

            # Check if the id exists in the database
            if not collection3.find_one({"_id": ObjectId(id)}):
                return jsonify({"error": "ID does not exist"}), 404

            # If the user does not select a file, the browser submits an empty file without a filename
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400

            file_name = f"{file.filename}"

            # Upload the file to DigitalOcean Spaces and get the file URL
            file_url = upload_to_digitalocean(file, file_name, device_type, id)  # Pass id parameter here

            return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

        # elif request.method == 'DELETE':

        #     data = request.json
        #     object_key = data.get('object_key')

        #     if object_key is None:
        #         return jsonify({"error": "No file specified for deletion"}), 400

        #     # Delete the file from DigitalOcean Spaces
        #     s3 = boto3.client('s3',
        #     aws_access_key_id=DO_ACCESS_KEY,
        #     aws_secret_access_key=DO_SECRET_KEY,
        #     endpoint_url=DO_SPACES_ENDPOINT
        # )
        #     # filename = request.json.get('filename')  # Assuming you send the filename in the request body

        #     delete_file_from_digitalocean()

        #     s3.delete_object(Bucket=DO_BUCKET_NAME, Key=object_key)

        #     files_collection.delete_one({'filename': file_name})

        #     return {'message': f'{file_name} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_from_digitalocean():
    try:
        s3 = boto3.client('s3',
        aws_access_key_id=DO_ACCESS_KEY,
        aws_secret_access_key=DO_SECRET_KEY,
        endpoint_url=DO_SPACES_ENDPOINT
    )

        # Delete the file from DigitalOcean Spaces
        data = request.json
        object_key = data.get('object_key')

        # Delete the object from the Space
        response = s3.delete_object(Bucket=DO_BUCKET_NAME, Key=object_key)

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

def delete_file_from_mongodb(file_name):
    # Delete the file information from MongoDB
    files_collection.delete_one({'filename': file_name})

# Check if file exists in DigitalOcean Spaces bucket
def file_exists_in_digitalocean(filename):
    s3 = boto3.client('s3',
        aws_access_key_id=DO_ACCESS_KEY,
        aws_secret_access_key=DO_SECRET_KEY,
        endpoint_url=DO_SPACES_ENDPOINT
    )
    try:
        s3.head_object(Bucket=DO_BUCKET_NAME, Key=filename)
        return True
    except:
        return False

@app.route('/events/image/<id>/<filename>', methods=['DELETE'])
@jwt_required()
def delete_uploaded_image(id, filename):
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid Object ID"}), 404

    if not allowed_file(filename):
        return jsonify({"error": "Invalid filename format"}), 404

    try:
        
        delete_file_from_digitalocean()
        delete_file_from_mongodb(filename)

        return {'message': f'File {filename} for ID {id} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

s3 = boto3.client('s3',
                  aws_access_key_id=DO_ACCESS_KEY,
                  aws_secret_access_key=DO_SECRET_KEY,
                  endpoint_url=DO_SPACES_ENDPOINT)
    
@app.route('/events/image', methods=['DELETE'])
@jwt_required()
def delete_object():
    try:
        # Get the object key from the request
        data = request.json
        object_key = data.get('object_key')

        # Delete the object from the Space
        response = s3.delete_object(Bucket=DO_BUCKET_NAME, Key=object_key)

        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
api.add_resource(SubscribeResource, "/newsletter-signup")
api.add_resource(UnsubscribeResource, "/unsubscribe")
api.add_resource(SubscribersListResource, "/newsletter-signup")

# "/events/image/{id}/{filename}": {
#         "delete": {
#           "summary": "Delete Event Image Info from database",
#           "description": "This API Endpoint will delete event image info from database.\n\n__Usage__:\n\n1) Click on the **Try it out** button.\n\n2) Click on the **Execute** button to submit the request.\n\n**The below table defines the HTTP Status codes that this API may return**\n\n<table>\n  <tr>\n    <td>Status Code</td>\n    <td>Description</td>\n    <td>Reason</td>\n  </tr>\n  <tr>\n    <td>200</td>\n    <td>Event Image Data</td>\n    <td>File abc.jpg deleted successfully.</td>\n  </tr>\n  <tr>\n    <td>401</td>\n    <td>Unauthorized</td>\n    <td>If Missing Authorization Header.</td>\n  </tr>\n  <tr>\n    <td>404</td>\n    <td>Not Found</td>\n    <td>File Not Found</td>\n  </tr>\n  <tr>\n    <td>500</td>\n    <td>Server Error</td>\n    <td>If Internal server error occured.</td>\n  </tr>\n</table>",       
#           "security":[{"JWT": {} }],
#           "tags": [
#             "Event"
#           ],
#           "parameters": [
#             {
#               "in": "path",
#               "name": "id",
#               "required": true,
#               "description": "Delete Event Image",
#               "schema": {
#                 "$ref": "#/components/schemas/id"
#               }
#             },
#             {
#               "in": "path",
#               "name": "filename",
#               "required": true,
#               "description": "Image Filename",
#               "schema": {
#                   "type": "string"
#               }
#           }
#           ],
#           "responses": {
#             "200": {
#               "description": "Event Image Data",
#               "content": {
#                 "application/json": {
#                   "schema": {
#                     "$ref": "#/components/serverResponseExample/deleteEventImageByIdSuccess"
#                   }
#                 }
#               }
#             },
#             "401": {
#               "description": "Unauthorized Error",
#               "content": {
#                 "application/json": {
#                   "schema": {
#                     "$ref": "#/components/serverResponseExample/unauthorizedIdError"
#                   }
#                 }
#               }
#             },
#             "404": {
#               "description": "Not Found Error",
#               "content": {
#                 "application/json": {
#                   "schema": {
#                     "$ref": "#/components/serverResponseExample/getEventByIdNotFoundError"
#                   }
#                 }
#               }
#             },
#             "500": {
#               "description": "Server Error",
#               "content": {
#                 "application/json": {
#                   "schema": {
#                     "$ref": "#/components/serverResponseExample/serverError"
#                   }
#                 }
#               }
#             }
#           }
#         }
#       },

# # Delete a newsletter
# @app.route('/newsletter-signup/<id>', methods=['DELETE'])
# @jwt_required()
# def delete_newsletter(id):
#     id = ObjectId(id)
#     result = collection4.delete_one({"_id": ObjectId(id)})

#     if result.deleted_count > 0:
#         return jsonify({"message": "Subscriber deleted successfully"})
#     else:
#         return jsonify({"error": "Subscriber not found or not deleted"}), 404

# Run the flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

# apis = [
#     "http://localhost:8080/book_now",
#     "http://localhost:8080/contacts",
#     "http://localhost:8080/events",
#     "http://localhost:8080/newsletters"
#     # Add more endpoints as needed
# ]

# @app.route('/getAllData', methods=['GET'])
# def get_aggregated_data():
#     aggregated_data = {}
#     # Get a list of all collection names in the database
#     collections = db.list_collection_names()

#     for collection_name in collections:
#         # Retrieve all documents from the current collection
#         collection_data = list(db[collection_name].find())
#           # Convert ObjectId to string in each document
#         for entry in collection_data:
#             entry['_id'] = str(entry['_id'])
#         aggregated_data[collection_name] = collection_data

#     return jsonify(aggregated_data)

#     # User model

# class User:
#     def __init__(self, username, password):
#         self.username = username
#         self.password = generate_password_hash(password)

# # Register endpoint for both admins and users

# class Register(Resource):
#     def post(self):
#         data = request.get_json()
#         username = data.get('username')
#         password = data.get('password')
#         role = data.get('role', 'user')  # Default role is 'user'
#         if not username or not password:
#             return {'message': 'Both username and password are required'}, 400
#         if collection.find_one({'username': username}):
#             return {'message': 'Username already exists'}, 400
#         hashed_password = bcrypt.generate_password_hash(
#             password).decode('utf-8')
#         collection.insert_one(
#             {'username': username, 'password': hashed_password, 'role': role})
#         return {'message': 'User registered successfully'}, 201

# # Login endpoint for admins

# class AdminLogin(Resource):
#     def post(self):
#         data = request.get_json()
#         username = data.get('username')
#         password = data.get('password')
#         user = collection.find_one({'username': username, 'role': 'admin'})
#         if not user or not bcrypt.check_password_hash(user['password'], password):
#             return {'message': 'Invalid admin credentials'}, 401
#         access_token = create_access_token(identity=username)
#         return {'access_token': access_token}, 200

# # Login endpoint for users


# class UserLogin(Resource):
#     def post(self):
#         data = request.get_json()
#         username = data.get('username')
#         password = data.get('password')
#         user = collection.find_one({'username': username, 'role': 'user'})
#         if not user or not bcrypt.check_password_hash(user['password'], password):
#             return {'message': 'Invalid user credentials'}, 401
#         access_token = create_access_token(identity=username)
#         return {'access_token': access_token}, 200

# api.add_resource(Register, '/register')
# api.add_resource(AdminLogin, '/admin/login')
# api.add_resource(UserLogin, '/user/login')

# blacklist = set()  # Set to store revoked tokens

# @app.route('/logout', methods=['DELETE'])
# @jwt_required()
# def logout():
#     jti = get_jwt()['jti']
#     blacklist.add(jti)
#     return jsonify({"message": "Successfully logged out"}), 200


# @jwt.token_in_blocklist_loader
# def check_if_token_in_blacklist(jwt_header, jwt_data):
#     jti = jwt_data['jti']
#     return jti in blacklist 

# # Flask-BasicAuth configuration
# app.config['BASIC_AUTH_USERNAME'] = 'admin'
# app.config['BASIC_AUTH_PASSWORD'] = 'password'
# basic_auth = BasicAuth(app)

# # Mock user data (for basic auth purposes)
# USERS = {
#     'user1': 'password1',
#     'user2': 'password2',
#     'admin': 'password'  # Admin credentials
# }

# class SecretResource(Resource):
#     @basic_auth.required
#     def get(self):
#         return "Hello, {}!".format(auth.current_user())

# api.add_resource(SecretResource, '/')

# "/getAllData":{
#         "get": {
#           "tags": [
#             "Default"
#           ],
#           "summary": "Return All Data",
#           "description": "This endpoint will get all bookings",
#           "security":[{"JWT": {} }],
#           "produces": "['application/json']",
#           "responses": {
#             "200": {
#               "description": "All Data",
#               "content": {
#                 "application/json": {
#                 }
#               }
#             }
#           }
#         }
#       }
