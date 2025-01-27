import os, base64
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend


# Cargar las variables de entorno desde el archivo .env
load_dotenv()
# Obtener la clave de cifrado desde las variables de entorno
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()

def encrypt_data(data):
    """Cifra los datos sensibles (como números de tarjeta)."""
    iv = os.urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Añadir padding al dato para que sea un múltiplo de 16 bytes
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Cifrar los datos
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Devolver el IV y el dato cifrado codificados en base64
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_data(encrypted_data):
    """Descifra los datos cifrados."""
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]  # Extraer el IV
    cipher_data = encrypted_data[16:]  # Extraer el dato cifrado

    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar los datos
    padded_data = decryptor.update(cipher_data) + decryptor.finalize()

    # Eliminar el padding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode()

app = Flask(__name__)
app.secret_key = os.urandom(24)


# Conexión a la base de datos
def get_db_connection():
    host = os.getenv('DB_HOST')
    user = os.getenv('DB_USER')
    password = os.getenv('DB_PASSWORD')
    database = os.getenv('DB_NAME')
    return mysql.connector.connect(
        host=host, user=user, password=password, database=database
    )

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Si no está autenticado, redirigir al login

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute('SELECT * FROM products')
        products = cursor.fetchall()

        # Obtener los productos del carrito, incluyendo cart_id
        cursor.execute('''
            SELECT cart.id AS cart_id, products.name, products.price, cart.quantity, products.image
            FROM cart
            JOIN products ON cart.product_id = products.id
            WHERE cart.user_id = %s
        ''', (user_id,))
        cart_items = cursor.fetchall()

        # Calcular el total del carrito
        total = sum(item['price'] * item['quantity'] for item in cart_items)

        return render_template('index.html', products=products, cart_items=cart_items, total=total)
    except mysql.connector.Error as err:
        flash(f"Error en la base de datos: {err}", 'error')
    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Verificamos si el usuario existe
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            
            if user:
                # Si el usuario existe, verificamos la contraseña
                if check_password_hash(user['password_hash'], password):
                    session['user_id'] = user['id']
                    return redirect(url_for('index'))
                else:
                    flash('Contraseña incorrecta', 'error')  # Mensaje si la contraseña es incorrecta
            else:
                flash('Usuario no encontrado', 'error')  # Mensaje si el usuario no existe
            return redirect(url_for('login'))  # Redirige al login en cualquier caso
        except mysql.connector.Error as err:
            flash(f"Error en la base de datos: {err}", 'error')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')


# Ruta para agregar productos al carrito
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash('Por favor, inicia sesión primero.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificar si el producto ya está en el carrito
        cursor.execute('SELECT * FROM cart WHERE product_id = %s AND user_id = %s', (product_id, user_id))
        existing_item = cursor.fetchone()

        if existing_item:
            # Si el producto ya está en el carrito, incrementar la cantidad
            cursor.execute('UPDATE cart SET quantity = quantity + 1 WHERE product_id = %s AND user_id = %s', (product_id, user_id))
            conn.commit()
            flash('Producto cantidad incrementada en el carrito.', 'success')
        else:
            # Si no está en el carrito, agregar el producto
            cursor.execute(
                'INSERT INTO cart (product_id, user_id, quantity) VALUES (%s, %s, 1)',
                (product_id, user_id)
            )
            conn.commit()
            flash('Producto agregado al carrito.', 'success')
    except mysql.connector.Error as err:
        flash(f"Error en la base de datos: {err}", 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('index'))




@app.route('/update_cart/<int:cart_id>', methods=['POST'])
def update_cart(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    action = request.form.get('action')
    conn = get_db_connection()
    if not conn:
        return "Error al conectar con la base de datos. Por favor, intente más tarde."

    cursor = conn.cursor()

    if action == 'increase':
        cursor.execute('UPDATE cart SET quantity = quantity + 1 WHERE id = %s AND user_id = %s', (cart_id, session['user_id']))
    elif action == 'decrease':
        cursor.execute('UPDATE cart SET quantity = quantity - 1 WHERE id = %s AND user_id = %s AND quantity > 1', (cart_id, session['user_id']))
    elif action == 'remove':
        cursor.execute('DELETE FROM cart WHERE id = %s AND user_id = %s', (cart_id, session['user_id']))
    
    conn.commit()
    conn.close()

    # Redirige al carrito sin cambiar a la página principal
    return redirect(url_for('index') + '?cart=true')  # Mantiene el carrito en la vista actual


@app.route('/checkout', methods=['POST'])
def checkout():
    # Obtener los datos del usuario desde la sesión (suponiendo que el usuario está autenticado)
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Conexión a la base de datos
    conn = get_db_connection()
    if not conn:
        return "Error al conectar con la base de datos. Por favor, intente más tarde."

    cursor = conn.cursor()

    # Obtener los datos del usuario desde la tabla 'user_data' (ya no necesitamos recibirlos desde el formulario)
    cursor.execute('SELECT first_name, last_name, phone, address, card FROM user_data WHERE user_id = %s', (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        return "Error: No se encontraron los datos del usuario."

    first_name, last_name, phone, address, card = user_data  # Desempaquetamos los datos
    # Descifrar el número de tarjeta
    decrypt_card = decrypt_data(card)

    #mostrar la información del usuario
    # print(f"Nombre: {first_name} {last_name}")
    # print(f"Teléfono: {phone}")
    # print(f"Dirección: {address}")
    # print(f"Número de tarjeta: {decrypt_card}")


    # Obtener los ítems del carrito
    cursor.execute('SELECT product_id, quantity FROM cart WHERE user_id = %s', (user_id,))
    cart_items = cursor.fetchall()  # Esto devolverá una lista de tuplas

    # Insertar los datos de la orden en la tabla 'orders_complete'
    for item in cart_items:
        # Obtener los detalles del producto
        cursor.execute('SELECT name, price, image FROM products WHERE id = %s', (item[0],))  # Acceder por índice
        product = cursor.fetchone()

        if not product:
            continue  # Si no se encuentra el producto, continuamos con el siguiente ítem

        # Acceder a los valores del producto usando índices
        product_name = product[0]  # nombre del producto
        product_price = product[1]  # precio del producto
        product_image = product[2]  # imagen del producto

        # Insertar la orden en 'orders_complete'
        cursor.execute('''INSERT INTO orders_complete (user_id, product_name, product_price, product_image, quantity)
                  VALUES (%s, %s, %s, %s, %s)''', 
                (user_id, product_name, product_price, product_image, item[1]))  # item[1] es la cantidad

    # Limpiar el carrito después de la compra
    cursor.execute('DELETE FROM cart WHERE user_id = %s', (user_id,))
    conn.commit()
    conn.close()

    flash('Compra exitosa. Gracias por su compra.', 'success')

    return redirect(url_for('index'))





@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Eliminar la sesión
    return redirect(url_for('login'))

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        first_name = request.form['first-name']
        last_name = request.form['last-name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        card = request.form['card']

        # Cifrar los datos sensibles antes de guardarlos en la base de datos
        card = encrypt_data(card)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, first_name, last_name, email) VALUES (%s, %s, %s, %s, %s)',
                (username, password_hash, first_name, last_name, email)
            )
            user_id = cursor.lastrowid
            cursor.execute(
                'INSERT INTO user_data (first_name, last_name, phone, address, card, user_id) VALUES (%s, %s, %s, %s, %s, %s)',
                (first_name, last_name, phone, address, card, user_id)
            )
            conn.commit()
            flash('Registro exitoso. Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Error en la base de datos: {err}", 'error')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')



if __name__ == '__main__':
    app.run(debug=True)
