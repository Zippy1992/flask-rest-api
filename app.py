from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from google.cloud import storage
from google.cloud.aiplatform_v1 import PredictionServiceClient
from google.cloud.aiplatform_v1.types import PredictRequest
from google.protobuf import struct_pb2

import os
import tempfile

# ✅ Step 1: Inject credentials from Render environment
if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON"):
    json_path = os.path.join(tempfile.gettempdir(), "gcp_key.json")
    with open(json_path, "w") as f:
        f.write(os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"])
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = json_path

app = Flask(__name__)

# ✅ JWT Secret
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)

# ✅ Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# ✅ User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ✅ Initialize DB
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return "✅ Flask API with JWT + Vertex AI Summarizer is running!"

@app.route('/debug-users')
def debug_users():
    return jsonify([{'id': u.id, 'username': u.username} for u in User.query.all()])

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.username)
    return jsonify({'access_token': access_token}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello, {current_user}. You are authorized!'}), 200

@app.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    current_user = get_jwt_identity()
    data = request.get_json()
    input_text = data.get("input", "")
    result = {"prediction": input_text.upper()}
    return jsonify({
        "user": current_user,
        "input": input_text,
        "result": result
    })

# ✅ Upload logic
ALLOWED_EXTENSIONS = {'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_gcs(bucket_name, source_file_path, destination_blob_name):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(source_file_path)
    return f"gs://{bucket_name}/{destination_blob_name}"

def summarize_with_vertex(gcs_uri):
    from google.cloud.aiplatform_v1 import PredictionServiceClient
    from google.cloud.aiplatform_v1.types import PredictRequest
    from google.protobuf import struct_pb2

    client = PredictionServiceClient()

    endpoint = client.endpoint_path(
        project="strategic-block-464807-a1",  # your project ID
        location="us-central1",
        endpoint="text-bison@001"
    )

    # ✅ Create Struct manually
    instance = struct_pb2.Struct()
    instance.fields["content"].string_value = f"Summarize this document stored at: {gcs_uri}"

    parameters = struct_pb2.Struct()
    parameters.fields["temperature"].number_value = 0.2

    request = PredictRequest(
        endpoint=endpoint,
        instances=[instance],  # ✅ Must be list of Struct
        parameters=parameters  # ✅ Must be Struct
    )

    response = client.predict(request=request)

    return response.predictions[0].fields["content"].string_value


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported file type'}), 400

    current_user = get_jwt_identity()
    filename = secure_filename(file.filename)
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    file.save(temp_path)

    bucket_name = "doc-summarizer-uploads"
    gcs_uri = upload_to_gcs(bucket_name, temp_path, filename)

    summary = summarize_with_vertex(gcs_uri)

    return jsonify({
        "message": f"File received for {current_user}",
        "filename": filename,
        "gcs_uri": gcs_uri,
        "summary": summary
    })

@app.route('/routes')
def list_routes():
    return jsonify([str(rule) for rule in app.url_map.iter_rules()])

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
