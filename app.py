from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
import tempfile
from werkzeug.utils import secure_filename


app = Flask(__name__)

# 🛡️ JWT secret key (change this in production or use env variable)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)

# 🗄️ Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# 👤 User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# 🔧 Create database (if not exists)
with app.app_context():
    db.create_all()

@app.route('/debug-users')
def debug_users():
    return jsonify([{'id': u.id, 'username': u.username} for u in User.query.all()])

# ✅ Home route
@app.route('/')
def home():
    return "✅ Flask API with JWT is running on Render!"

# 🟢 Register
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    print(f"[LOG] Registration request: {data}")  # <-- This gets printed to Render logs

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    print(f"[LOG] User registered: {new_user.username}")  # <-- Also goes to logs
    return jsonify({'message': 'User registered successfully'}), 201


# 🔵 Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.username)
    return jsonify({'access_token': access_token}), 200

@app.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    # Example logic (e.g., dummy prediction or call model)
    input_text = data.get("input", "")
    result = {"prediction": input_text.upper()}  # mock

    return jsonify({
        "user": current_user,
        "input": input_text,
        "result": result
    })


# 🔐 Protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello, {current_user}. You are authorized!'}), 200

@app.route('/routes')
def list_routes():
    return jsonify([str(rule) for rule in app.url_map.iter_rules()])


ALLOWED_EXTENSIONS = {'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

    # Save temporarily
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    file.save(temp_path)

    return jsonify({'message': f'File received for {current_user}', 'filename': filename}), 200

# 🚀 Start server (Render needs 0.0.0.0)
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
