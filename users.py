import boto3  # aws dynamodb sdk
import uuid

# connect and define tables
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
usersTable = dynamodb.Table('users')

# create predefined users
def create_user(role, sub):
    item = {
        'id': '',         
        'sub': sub,
        'role': role
    }
    
    item['id'] = str(uuid.uuid4().int)[:16]  # 16 digit string to mirror google datastore

    usersTable.put_item(Item=item)

create_user('admin', 'auth0|6836637d2724f189910bc746')
create_user('instructor', 'auth0|683663a5f4d297815b82fe7d')
create_user('instructor', 'auth0|683663bc2724f189910bc74b')
create_user('student', 'auth0|683663d3f4d297815b82fe80')
create_user('student', 'auth0|683663e32724f189910bc750')
create_user('student', 'auth0|683663f22724f189910bc751')
create_user('student', 'auth0|683664052724f189910bc755')
create_user('student', 'auth0|68366412f4d297815b82fe86')
create_user('student', 'auth0|6836641ef4d297815b82fe87')