from flask import Flask, render_template, request, redirect, make_response, session, url_for

import boto3
import jwt
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
# Configure the secret key
app.secret_key = os.getenv('APP_SECRET')


# Amazon Cognito credentials
REGION = os.getenv('REGION')
USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')

s3 = boto3.client(
        's3',
        aws_access_key_id= os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name= REGION
        
    )


# Initialize boto3 client for Cognito
cognito_client = boto3.client("cognito-idp", region_name=REGION)

@app.route("/")
def index():
    access_token = request.cookies.get("access_token")
    if access_token:
        username = validate_token(access_token)
        if username: 
            sub = extract_sub_from_id_token(request.cookies.get('idtoken'))
            keys = list_files_in_bucket(sub)
            # prefix = 'https://linkit.s3.amazonaws.com/'
            # result = [prefix + key for key in keys]
            return render_template("welcome.html", username=username, keys = keys)
    return render_template("login.html")

@app.route('/upload', methods=['POST'])
def upload():
    # Get the uploaded file
    uploaded_file = request.files['file']

    # Extract user's sub from the ID token cookie
    sub = extract_sub_from_id_token(request.cookies.get('idtoken'))

    # Specify the bucket name and prefix
    bucket_name = 'linkit'
    prefix = f'user-{sub}/'  # Specify the desired prefix for uploads
    
    # Save the uploaded file to S3 with the specified prefix
    s3.upload_fileobj(uploaded_file, bucket_name, f"{prefix}{uploaded_file.filename}")

    # Redirect back to the welcome page
    return redirect(url_for('index'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        access_token,idToken = authenticate_user(username, password)
        if access_token:
            print("if access token")
            response = make_response(redirect("/"))
            response.set_cookie("access_token", access_token)
            response.set_cookie("idtoken",idToken)
            return response
        else:
            print("else access token")
            
            return render_template("login.html", error="Invalid username or password")

    # Render the login form for GET requests
    return render_template("login.html")

@app.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.set_cookie("access_token", "", expires=0)  # Delete cookie
    response.set_cookie("idtoken", "", expires=0)  # Delete cookie
    return response

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            response = cognito_client.sign_up(
                ClientId=CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email}
                ]
            )
            session['username'] = username 
            return redirect("/verification")
        except cognito_client.exceptions.UsernameExistsException:
            return render_template("registration.html", error="Username already exists")

    # Render the registration form for GET requests
    return render_template("registration.html")

@app.route("/verification", methods=["GET", "POST"])
def verification():
    if request.method == "POST":
        verification_code = request.form["verification_code"]
        username = session.get("username")
        if not username:
            return redirect("/")  # Redirect if username is not found in session
        try:
            cognito_client.confirm_sign_up(
                ClientId=CLIENT_ID,
                Username=username,
                ConfirmationCode=verification_code
            )
            session.pop('username')
            # print account created flash message
            return render_template("login.html", success="Account created successfully")
            return redirect("/")
        except cognito_client.exceptions.AliasExistsException :
            session.pop('username')
            return render_template("login.html", error="User Already exists !")
        except :
            return render_template("verification.html", error="Invalid verification code")
        
            

    return render_template("verification.html")


@app.route('/delete', methods=['POST'])
def delete():
    # Get the file name to be deleted from the form data
    file_name = request.form.get('file')
    print(file_name)

    # Extract user's sub from the ID token cookie
    sub = extract_sub_from_id_token(request.cookies.get('idtoken'))

    # Specify the bucket name and prefix
    bucket_name = 'linkit'
    prefix = f'user-{sub}/'  # Specify the prefix where files are uploaded
    
    # Delete the file from the S3 bucket
    print('deleting ------------- '+f"{file_name}")
    s3.delete_object(Bucket=bucket_name, Key=file_name)

    # Redirect back to the welcome page
    return redirect(url_for('index'))


# @app.route('/try', methods=['GET','POST'])
# def try():
# # method to let people try without signing up or logging in
#     if 

def authenticate_user(username, password):
    try:
        print("in authentication part")
        response = cognito_client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
            ClientId=CLIENT_ID
        )  
        return response["AuthenticationResult"]["AccessToken"], response["AuthenticationResult"]["IdToken"]
    except cognito_client.exceptions.NotAuthorizedException:
        return None

def validate_token(access_token):
    try:
        response = cognito_client.get_user(
            AccessToken=access_token
        )

        return response["Username"]
    except cognito_client.exceptions.NotAuthorizedException:
        return None
    
def extract_sub_from_id_token(id_token):
    try:
        # Decode the ID token
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        
        # Extract the 'sub' claim
        user_sub = decoded_token.get('sub')
        
        return user_sub
    except jwt.DecodeError as e:
        # Handle decoding errors
        print(f"Error decoding ID token: {e}")
        return None
    except jwt.InvalidTokenError as e:
        # Handle invalid token errors
        print(f"Invalid ID token: {e}")
        return None

def list_files_in_bucket(prefix):
    # Initialize the S3 client
    

    # List objects in the bucket under the specified prefix
    response = s3.list_objects_v2(Bucket='linkit', Prefix=f'user-{prefix}/')

    # Extract object keys from the response
    object_keys = [obj['Key'] for obj in response.get('Contents', [])]

    # filenames = []
    # for name in object_keys:
    #     filenames.append((f'https://linkit.s3.amazonaws.com/{name}'))

    # return filenames[1:]
    return object_keys


if __name__ == "__main__":
    app.run(debug=True)