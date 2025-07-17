from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from google.cloud import storage
from vertexai.preview.language_models import TextGenerationModel
import vertexai

import os
import tempfile

# ✅ Inject credentials from Render secret env var (GOOGLE_APPLICATION_CREDENTIALS_JSON)
if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON"):
    json_path = os.path.join(tempfile.gettempdir(), "gcp_key.json")
    with open(json_path, "w") as f:
        f.write(os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"])
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = json_path

# ✅ Initialize Flask app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ✅ User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# ✅ Allowed file types
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
    vertexai.init(project="zippy-genai-summarizer", location="us-central1")  # ✅ Set your project + region
    model = TextGenerationModel.from_pretrained("text-bison@001")

    prompt = f"Summarize the document available at this Google Cloud Storage URI:\n{gcs_uri}"

    response = model.predict(
        prompt=prompt,
        temperature=0.2,
        max_output_tokens=512
    )
    return response.text

# ✅ Routes
@app.route('/')
def home():
    return "✅ Flask API with JWT + Vertex AI Summarizer is running!"

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
    token = create_access_token(identity=user.username)
    return jsonify({'access_token': token}), 200

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(temp_path)

        bucket_name = "doc-summarizer-uploads"  # ✅ Ensure bucket exists in us-central1
        gcs_uri = upload_to_gcs(bucket_name, temp_path, filename)
        summary = summarize_with_vertex(gcs_uri)

        return jsonify({
            "user": current_user,
            "filename": filename,
            "gcs_uri": gcs_uri,
            "summary": summary
        })

    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user = get_jwt_identity()
    return jsonify({'message': f'Hello {user}, you are authorized.'})

@app.route('/routes')
def list_routes():
    return jsonify([str(rule) for rule in app.url_map.iter_rules()])

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
