from flask import Flask, request, jsonify, send_file, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import pyotp
import qrcode
from io import BytesIO

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'data_task1'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

mysql = MySQL(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        
        token = token.replace('Bearer ', '').strip()
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Invalid token!'}), 403
        
        return f(*args, **kwargs)
    return decorated

# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    secret = pyotp.random_base32()

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                (username, hashed_password, secret))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User registered successfully. Please login to get QR code.'})

# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid username or password'}), 401

    session.clear()

 
    session['username'] = username

    otp_auth_url = pyotp.totp.TOTP(user['twofa_secret']).provisioning_uri(username, issuer_name="FlaskApp")
    qr = qrcode.make(otp_auth_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')

# Verify OTP Route
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if 'username' not in session:
        return jsonify({'message': 'Session expired. Please login again.'}), 401

    username = session['username']
    data = request.get_json()
    otp_code = data.get('otp')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    totp = pyotp.TOTP(user['twofa_secret'])
    if not totp.verify(otp_code):
        return jsonify({'message': 'Invalid OTP code'}), 401

    
    token = jwt.encode({'id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                        app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

@app.route('/products', methods=['POST'])
@token_required
def add_product():
    data = request.get_json()
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                (data['name'], data['description'], data['price'], data['quantity']))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product added successfully'})

@app.route('/products', methods=['GET'])
@token_required
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()
    return jsonify(products)

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    data = request.get_json()
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                (data['name'], data['description'], data['price'], data['quantity'], product_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
