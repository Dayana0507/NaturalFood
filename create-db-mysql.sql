-- Crear la base de datos
CREATE DATABASE IF NOT EXISTS proyecto;
USE proyecto;

-- Tabla de productos
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(8, 2) CHECK (price > 0),
    image VARCHAR(255)
);

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) UNIQUE
);

-- Tabla de carrito
CREATE TABLE IF NOT EXISTS cart (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1 CHECK (quantity > 0),
    user_id INT NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabla de órdenes completas
CREATE TABLE IF NOT EXISTS orders_complete (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_name VARCHAR(255),
    product_price DECIMAL(8, 2) CHECK (product_price > 0),
    product_image VARCHAR(255),
    quantity INT CHECK (quantity > 0),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabla de datos del usuario
CREATE TABLE IF NOT EXISTS user_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    card VARCHAR(100),
    user_id INT UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Crear índices
CREATE INDEX idx_cart_user_id ON cart(user_id);
CREATE INDEX idx_cart_product_id ON cart(product_id);
CREATE INDEX idx_orders_user_id ON orders_complete(user_id);

-- Insertar datos de prueba
INSERT INTO products (name, price, image) VALUES
('Soda', 10.99, 'https://app-front-proyecto.s3.us-east-1.amazonaws.com/soda.jpg'),
('Chia', 20.99, 'https://app-front-proyecto.s3.us-east-1.amazonaws.com/chia.png'),
('Té Caliente', 30.99, 'https://app-front-proyecto.s3.us-east-1.amazonaws.com/T%C3%A9+caliente.jpg');
