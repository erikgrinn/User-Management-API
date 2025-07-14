### Sources:
# https://auth0.com/docs/quickstart/webapp/python
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
# https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/guide/dynamodb.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/programming-with-python.html
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
# Auth0 configuration: must enable password

from flask import Flask, request, jsonify, send_file, render_template, url_for, redirect

import boto3  # aws dynamodb sdk
from boto3.dynamodb.conditions import Key, Attr  # for Table.scan()
import uuid  # python id package since dyanmodb does not auto-generate
import io
from requests_toolbelt import MultipartEncoder
import requests
import json

from urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# connect and define tables
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
usersTable = dynamodb.Table('users')
coursesTable = dynamodb.Table('courses')


# s3 bucket client (instead of resource)
s3 = boto3.client('s3', region_name='us-east-1')
BUCKET = 'myawsbucket-photos-1'


# Update the values of the following 3 variables
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
DOMAIN = os.environ.get('AUTH0_DOMAIN')
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    # handle invalid request
    content = request.get_json()
    if not content or 'username' not in content or 'password' not in content:
    # if not content or content not in ['username', 'password']:
        return jsonify({"Error": "The request body is invalid"}), 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET,
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    r_json = r.json()
    if 'error' in r_json:
        return jsonify({"Error": "Unauthorized"}), 401
    
    r_json['token'] = r_json.get('id_token')
    return jsonify({'token': r_json['token']}), 200

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

@app.route('/')
def index():
    return "Please use postman for this API"

# GET users
@app.route('/users', methods=['GET'])
def get_users():
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.scan(  
            FilterExpression=Attr('sub').eq(payload['sub'])
        )
         
        if not response['Items'] or response['Items'][0]['role'] != 'admin':
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        response = usersTable.scan()  # scan looks at all entries
        users = response.get('Items', [])  # get items from response/scan    
        return jsonify(users)
    
    return jsonify({'Error': 'No Authorization header'})

# GET a user
@app.route('/users/<string:id>', methods=['GET'])
def get_user(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.get_item(
            Key={'id': id}
        )
        
        if 'Item' not in response:
            return {"Error": "No user with this user_id exists"}, 403
        
        item = response['Item']
        
        # verify matching user and jwt
        if item.get('sub') != payload['sub']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        # role specific responses:      
        if item.get('role') == 'admin':
            return jsonify(item)
        
        elif item.get('role') == 'instructor':
            if 'courses' not in item:
                item['courses'] = []
            return jsonify(item)
        
        elif item.get('role') == 'student':
            if 'courses' not in item:
                item['courses'] = []
            return jsonify(item)

        
    return jsonify({'Error': 'No Authorization header'})

# POST an avatar
@app.route('/users/<string:id>/avatar', methods=['POST'])
def post_avatar(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.get_item(
            Key={'id': id}
        )
        
        if 'Item' not in response:
            return {"Error": "No avater found"}, 403
        
        item = response['Item']
        
        # verify matching user and jwt
        if item.get('sub') != payload['sub']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        
        # Upload Image:
        # Any files in the request will be available in request.files object
        # Check if there is an entry in request.files with the key 'file'
        if 'file' not in request.files:
            return ({'Error': 'The request body is invalid'}), 400
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']
        # If the multipart form data has a part with name 'tag', set the
        # value of the variable 'tag' to the value of 'tag' in the request.
        # Note we are not doing anything with the variable 'tag' in this
        # example, however this illustrates how we can extract data from the
        # multipart form data in addition to the files.
        if 'tag' in request.form:
            tag = request.form['tag']
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Create unique file_name for user
        s3_file_name = f"{id}_avatar.png"
        # Upload the file into Cloud Storage
        s3.upload_fileobj(file_obj, BUCKET, s3_file_name)
        
        # update user in db with avatar_url
        avatar_url = f"{request.host_url}{'users'}/{id}/{'avatar'}"
        usersTable.update_item(
            Key={'id': id},
            UpdateExpression="SET avatar_url = :url, s3_file_name = :s3_name",
            ExpressionAttributeValues={':url': avatar_url, ':s3_name': s3_file_name}
        )
        
        return jsonify({'avatar_url': avatar_url}), 200

    return jsonify({'Error': 'No Authorization header'})

# GET an avatar
@app.route('/users/<string:id>/avatar', methods=['GET'])
def get_avatar(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.get_item(
            Key={'id': id}
        )
        
        if 'Item' not in response:
            return {"Error": "No business with this business_id exists"}, 403
        
        item = response['Item']
        
        # verify matching user and jwt
        if item.get('sub') != payload['sub']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        # Get Image:
        if 'avatar_url' in item:
            # Create a file object in memory using Python io package
            file_obj = io.BytesIO()
            # Get file_name
            file_name = item.get('s3_file_name')
            # Download the file from Cloud Storage to the file_obj variable
            s3.download_fileobj(BUCKET, file_name, file_obj)
            # Position the file_obj to its beginning
            file_obj.seek(0)
            # Send the object as a file in the response with the correct MIME type and file name
            return send_file(file_obj, mimetype='image/x-png', download_name=file_name)
        
        return jsonify({"Error": "Not found"}), 404
    
    return jsonify({'Error': 'No Authorization header'}) 

    
# DELETE an avatar
@app.route('/users/<string:id>/avatar', methods=['DELETE'])
def delete_avatar(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.get_item(
            Key={'id': id}
        )
        
        if 'Item' not in response:
            return {"Error": "No user with this user_id exists"}, 403
        
        item = response['Item']
        
        # verify matching user and jwt
        if item.get('sub') != payload['sub']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        # delete image:
        if 'avatar_url' in item:
            file_name = item.get('s3_file_name')
            # Delete the file from Cloud Storage
            s3.delete_object(Bucket=BUCKET, Key=file_name)
            
            usersTable.update_item(
                Key={'id': id},
                UpdateExpression="REMOVE avatar_url, s3_file_name"
            )
            
            return '', 204
        
        return jsonify({"Error": "Not found"}), 404
       
    return jsonify({'Error': 'No Authorization header'}) 

       
# POST a course
@app.route('/courses', methods=['POST'])
def post_course():
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = usersTable.scan(  
            FilterExpression=Attr('sub').eq(payload['sub'])
        )
        if not response['Items'] or response['Items'][0]['role'] != 'admin':
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        content = request.get_json()
        content['id'] = str(uuid.uuid4().int)[:16]  # 16 digit string to mirror google datastore
        
        required_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
        for field in required_fields:
            if field not in content:
                return jsonify({"Error": "The request body is invalid"}), 400

        # check if instructor_id exists
        response = usersTable.get_item(
            Key={'id': str(content['instructor_id'])}
        )
        if 'Item' not in response or response['Item']['role'] != 'instructor':
            return jsonify({"Error": "The request body is invalid"}), 400
                       
        coursesTable.put_item(Item=content) 
        
        content['self'] = f"{request.host_url}{'courses'}/{content['id']}"
        content['instructor_id'] = str(content['instructor_id']) 
        return jsonify(content), 201
    
    return jsonify({'Error': 'No Authorization header'}) 
        
        
# GET courses
@app.route('/courses', methods=['GET'])
def get_courses():
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))

    response = coursesTable.scan()  # scan looks at all entries
    courses = response.get('Items', [])  # get items from response/scan  
    for course in courses:
        course['self'] = f"{request.host_url}{'courses'}/{course['id']}" 
    
    # sort courses by subject
    courses_sorted = sorted(courses, key=lambda x: x.get('subject', ''))

    paginated_courses = courses_sorted[offset:offset+limit]
    next_link = f"{request.host_url}courses?limit={limit}&offset={offset+limit}"
    return jsonify({'courses': paginated_courses, 'next': next_link})


# GET a course
@app.route('/courses/<string:id>', methods=['GET'])
def get_course(id):

    response = coursesTable.get_item(
        Key={'id': id}
    )
    
    if 'Item' not in response:
        return {"Error": "Not found"}, 404
    
    item = response['Item']
    item['number'] = int(item['number'])
    item['self'] = f"{request.host_url}{'courses'}/{item['id']}" 

    return jsonify(item)

# PATCH a course
@app.route('/courses/<string:id>', methods=['PATCH'])
def patch_course(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        # only admin can update courses
        response = usersTable.scan(FilterExpression=Attr('sub').eq(payload['sub']))
        if not response['Items'] or response['Items'][0]['role'] != 'admin':
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        # get the course
        course_response = coursesTable.get_item(Key={'id': id})
        if 'Item' not in course_response:
            return jsonify({"Error": "Not found"}), 404

        # get fields to update
        content = request.get_json()
        if not content:
            return jsonify({"Error": "The request body is invalid"}), 400

        # validate instructor exists
        if 'instructor_id' in content:
            instructor_response = usersTable.get_item(Key={'id': content['instructor_id']})
            if 'Item' not in instructor_response or instructor_response['Item']['role'] != 'instructor':
                return jsonify({"Error": "The request body is invalid"}), 400

        # build update expression
        update_expression_temp = []
        expr_attr_vals = {}
        for key, value in content.items():
            update_expression_temp.append(f"{key} = :{key}")
            expr_attr_vals[f":{key}"] = value
            
        update_expression = "SET " + ", ".join(update_expression_temp)
        coursesTable.update_item(
            Key={'id': id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expr_attr_vals
        )

        # return the updated course
        updated_course = coursesTable.get_item(Key={'id': id})['Item']
        updated_course['self'] = f"{request.host_url}courses/{updated_course['id']}"
        return jsonify(updated_course), 200
    
    return jsonify({'Error': 'No Authorization header'}) 

        
# DELETE a course
@app.route('/courses/<string:id>', methods=['DELETE'])
def delete_course(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        response = coursesTable.get_item(
            Key={'id': id}
        )
        
        if 'Item' not in response:
            return {"Error": "Not found"}, 404
        
        item = response['Item']
        
        # only admin can delete courses
        response = usersTable.scan(FilterExpression=Attr('sub').eq(payload['sub']))
        if not response['Items'] or response['Items'][0]['role'] != 'admin':
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        # delete course:
        coursesTable.delete_item(
            Key={'id': id}
        )
        
        return '', 204
        
       
    return jsonify({'Error': 'No Authorization header'}) 

# PATCH/CREATE enrollments
@app.route('/courses/<string:id>/students', methods=['PATCH'])
def patch_enrollments(id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        # only admin or course instructor can update enrollments
        user_response = usersTable.scan(FilterExpression=Attr('sub').eq(payload['sub']))
        if not user_response['Items'] or user_response['Items'][0]['role'] not in ['admin', 'instructor']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        course_response = coursesTable.get_item(Key={'id': id})
        if 'Item' not in course_response:
            return jsonify({"Error": "Not found"}), 404

        course = course_response['Item']
        students = course.get('students', []) 
        students = set([int(s) for s in students]) # omit boto3 type artifacts, and set avoid duplicates
        
        if user_response['Items'][0]['role'] != 'admin' and str(course['instructor_id']) != str(user_response['Items'][0]['id']):
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        content = request.get_json()
        if content is None or 'add' not in content or 'remove' not in content:
            return jsonify({"Error": "The request body is invalid"}), 400

        # if student in both add and remove, or if student to remove is not enrolled
        add_set = set(content['add'])
        remove_set = set(content['remove'])
        if add_set & remove_set:
            return jsonify({"Error": "Enrollment data is invalid"}), 409
        # # if student to remove is not enrolled - not necessarily error according to specification
        # if not remove_set & students:
        #     return jsonify({"Error": "Enrollment data is invalid"}), 409


        # add students
        for student_id in content['add']:
            item_response = usersTable.get_item(Key={'id': str(student_id)})
            if 'Item' not in item_response or item_response['Item']['role'] != 'student':
                return jsonify({"Error": "Enrollment data is invalid"}), 409
            elif student_id in students: # if student already enrolled - redundant due to set 
                continue
            students.add(student_id)

        # remove students
        for student_id in content['remove']:
            item_response = usersTable.get_item(Key={'id': str(student_id)})
            if 'Item' not in item_response or item_response['Item']['role'] != 'student':
                return jsonify({"Error": "Enrollment data is invalid"}), 409
            elif student_id not in students: # if student not enrolled
                continue
            students.remove(student_id)

        # update course
        coursesTable.update_item(
            Key={'id': id},
            UpdateExpression="SET students = :students",
            ExpressionAttributeValues={':students': list(students)}
        )

        return '', 200
    
    return jsonify({'Error': 'No Authorization header'}) 

# GET all enrollments for course
@app.route('/courses/<string:course_id>/students', methods=['GET'])
def get_enrollments(course_id):
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify({"Error": "Unauthorized"}), 401

        # only admin or course instructor can update enrollments
        user_response = usersTable.scan(FilterExpression=Attr('sub').eq(payload['sub']))
    
        if not user_response['Items'] or user_response['Items'][0]['role'] not in ['admin', 'instructor']:
            return jsonify({"Error": "You don't have permission on this resource"}), 403
    
        course_response = coursesTable.get_item(Key={'id': course_id})
        if 'Item' not in course_response:
            return jsonify({"Error": "Not found"}), 404

        course = course_response['Item']
        students = course.get('students', [])
        
        if user_response['Items'][0]['role'] != 'admin' and str(course['instructor_id']) != str(user_response['Items'][0]['id']):
            return jsonify({"Error": "You don't have permission on this resource"}), 403
        
        return jsonify(list(students)), 200
    
    return jsonify({'Error': 'No Authorization header'}) 


# @app.route('/images', methods=['POST'])
# def store_image():
#     # Any files in the request will be available in request.files object
#     # Check if there is an entry in request.files with the key 'file'
#     if 'file' not in request.files:
#         return ('No file sent in request', 400)
#     # Set file_obj to the file sent in the request
#     file_obj = request.files['file']
#     # If the multipart form data has a part with name 'tag', set the
#     # value of the variable 'tag' to the value of 'tag' in the request.
#     # Note we are not doing anything with the variable 'tag' in this
#     # example, however this illustrates how we can extract data from the
#     # multipart form data in addition to the files.
#     if 'tag' in request.form:
#         tag = request.form['tag']
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Upload the file into Cloud Storage
#     s3.upload_fileobj(file_obj, BUCKET, file_obj.filename)
#     return ({'file_name': file_obj.filename}, 201)

# @app.route('/images/<file_name>', methods=['GET'])
# def get_image(file_name):
#     # Create a file object in memory using Python io package
#     file_obj = io.BytesIO()
#     # Download the file from Cloud Storage to the file_obj variable
#     s3.download_fileobj(BUCKET, file_name, file_obj)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Send the object as a file in the response with the correct MIME type and file name
#     return send_file(file_obj, mimetype='image/x-png', download_name=file_name)


# @app.route('/images/<file_name>', methods=['DELETE'])
# def delete_image(file_name):
#     # Delete the file from Cloud Storage
#     s3.delete_object(Bucket=BUCKET, Key=file_name)
#     return '',204


application = app
if __name__ == '__main__':
    # app.run(host='127.0.0.1', port=8080, debug=True)
    application.run(host='0.0.0.0', port=8080)