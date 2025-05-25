CREATE DATABASE image_detection_db;

USE image_detection_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE detections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    original_image VARCHAR(255) NOT NULL,
    ela_image VARCHAR(255) NOT NULL,
    mask_image VARCHAR(255) NOT NULL,
    highlighted_image VARCHAR(255) NOT NULL,
    result VARCHAR(50),
    tamper_ratio FLOAT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
