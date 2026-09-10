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

create_user('admin', 'auth0|6aa1ee4bc374847a251efd8f')
create_user('instructor', 'auth0|6aa1eeb1c374847a251efe01')
create_user('instructor', 'auth0|6aa1eed0c374847a251efe1f')
create_user('student', 'auth0|6aa1ef48431dd6f3522e708e')
create_user('student', 'auth0|6aa1ef5580c9b1ceb6c6f928')
create_user('student', 'auth0|6aa1ef628fa99f7f292b1213')
create_user('student', 'auth0|6aa1ef708fa99f7f292b1224')
create_user('student', 'auth0|6aa1ef778fa99f7f292b1226')
create_user('student', 'auth0|6aa1ef7fc374847a251efec2')