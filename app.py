from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from vertexai.preview.language_models import TextGenerationModel
from google.cloud import storage
import os
import tempfile

# ✅ Set credentials if injected as JSON (Render or other env)
if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON"):
    json_path = os.path.join(tempfile.gettempdir(), "gcp_key.json")
    with open(json_path, "w") as f:
        f.write(os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"])
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = json_path

app = Flask(__name__)

# ✅ App config
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB file limit

db = SQLAlchemy(app)
jwt = JWTManager(app)

ALLOWED_EXTENSIONS = {'txt', 'pdf'}

# ✅ User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# ✅ Utility: File extension check
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ Utility: Upload to GCS
def upload_to_gcs(bucket_name, source_file_path, destination_blob_name):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(source_file_path)
    return f"gs://{bucket_name}/{destination_blob_name}"

# ✅ Optional test function (can be called from CLI separately)
def test_upload_to_gcs():
    client = storage.Client()
    bucket = client.get_bucket('doc-summarizer-upload')
    blob = bucket.blob('test_upload.txt')
    blob.upload_from_string("This is a test upload from Flask app.")
    print("✅ Test upload successful")

def summarize_with_vertex(gcs_uri):
    try:
        model = TextGenerationModel.from_pretrained("text-bison")
        prompt = f"Summarize the document available at this Google Cloud Storage URI:\n{gcs_uri}"
        print("📨 Prompt being sent to Vertex AI:", prompt)

        response = model.predict(
            prompt=prompt,
            temperature=0.2,
            max_output_tokens=512
        )

        print("✅ Vertex AI returned summary.")
        return response.text

    except Exception as e:
        print("❌ Vertex AI error:", e)
        return f"[Vertex AI Error] {str(e)}"


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

        try:
            bucket_name = "doc-summarizer-upload"  # Ensure this exists in GCS
            gcs_uri = upload_to_gcs(bucket_name, temp_path, filename)
            summary = summarize_with_vertex(gcs_uri)
            return jsonify({
                "user": current_user,
                "filename": filename,
                "gcs_uri": gcs_uri,
                "summary": summary
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

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
    # Optional: Uncomment to test GCS upload locally only
    # test_upload_to_gcs()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
