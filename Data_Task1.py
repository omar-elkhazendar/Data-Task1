from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
import datetime
from functools import wraps
import os

app = Flask(__name__)


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'infosec_task2'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  
app.config['SECRET_KEY'] = 'your_secret_key'

mysql = MySQL(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = pyjwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/signup', methods=['POST'])
def signup():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data) 

        if not data or 'name' not in data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')  
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, username, password) VALUES (%s, %s, %s)",
                    (data['name'], data['username'], hashed_password))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data)  

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user = cur.fetchone()
        cur.close()

        
        if not user:
            return jsonify({'message': 'Invalid username or password'}), 401

        
        if not check_password_hash(user['password'], data['password']):
            return jsonify({'message': 'Invalid username or password'}), 401

        
        token = pyjwt.encode(
            {'id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
            app.config['SECRET_KEY'], 
            algorithm='HS256'
        )

        return jsonify({'token': token})

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500


@app.route('/users/<int:id>', methods=['PUT'])
@token_required
def update_user(id):
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data)  

        if not data or 'name' not in data or 'username' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET name=%s, username=%s WHERE id=%s", 
                    (data['name'], data['username'], id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        print("Error:", str(e)) 
        return jsonify({'error': str(e)}), 500




@app.route('/products', methods=['POST'])
@token_required
def add_product():
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (pname, description, price, stock, created_at) VALUES (%s, %s, %s, %s, NOW())", (data['pname'], data['description'], data['price'], data['stock']))
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

@app.route('/products/<int:pid>', methods=['GET'])
@token_required
def get_product(pid):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE pid = %s", (pid,))
    product = cur.fetchone()
    cur.close()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    return jsonify(product)

@app.route('/products/<int:pid>', methods=['PUT'])
@token_required
def update_product(pid):
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET pname=%s, description=%s, price=%s, stock=%s WHERE pid=%s", (data['pname'], data['description'], data['price'], data['stock'], pid))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<int:pid>', methods=['DELETE'])
@token_required
def delete_product(pid):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE pid = %s", (pid,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':  # Correct way to check main script
    app.run(debug=True)