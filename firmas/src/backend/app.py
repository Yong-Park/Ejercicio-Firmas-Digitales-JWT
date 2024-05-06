from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'yongpark20117'  # Cambia esto por tu propia clave secreta

users = {}  # Aquí almacenaremos los usuarios registrados

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            print(token)
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            print("testo")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print(data)
            current_user = users.get(data['username'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    users[data['username']] = {'password': hashed_password}
    return jsonify({'message': 'Usuario registrado exitosamente!'})

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('No se pudo verificar', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = users.get(auth.username)
    if not user or not check_password_hash(user['password'], auth.password):
        return make_response('No se pudo verificar', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    token = jwt.encode({'username': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token})


@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    token = request.headers['x-access-token']
    return jsonify({'message': 'Accedido a recursos protegidos', 'user': current_user, 'token': token})


if __name__ == '__main__':
    app.run(debug=True)
