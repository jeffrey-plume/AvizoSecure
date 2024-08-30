import sys
import os
import hashlib
import sqlite3
from datetime import datetime
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import (
    QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpinBox, QAction, QMainWindow, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem, QWidget, QGroupBox, QCheckBox
)
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class registerDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(registerDialog, self).__init__(parent)


        self.setWindowTitle("Please Input Credentials")
        self.setGeometry(150, 150, 300, 200)

        # Username and password inputs
        self.username_label = QtWidgets.QLabel("Username:", self)
        self.username_input = QtWidgets.QLineEdit(self)

        self.password_label = QtWidgets.QLabel("Password:", self)
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        # Login button
        self.register_button = QtWidgets.QPushButton("Apply", self)
        self.register_button.clicked.connect(self.handle_registration)

        # Layout setup
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.register_button)
        self.setLayout(layout)

        # Function to generate RSA key pair
    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    # Function to save private key to a file
    def save_private_key_to_file(self, private_key, username):
        private_key_file = f"{username}_private_key.pem"
        with open(private_key_file, "wb") as private_file:
            private_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            
    def handle_registration(self):
        # Get username and password
        username = self.username_input.text()
        password = self.password_input.text()

        # Hash the password
        password_hashed = hashlib.sha256(password.encode()).hexdigest()

        # Check credentials in the database
        if (username, password_hashed):
            self.current_user = username
            private_key, public_key = self.generate_rsa_key_pair()
        
            # Save the private key to a file
            self.save_private_key_to_file(private_key, username)
        
        # Serialize public key to PEM format for storage
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
                    # Connect to the SQLite database
            conn = sqlite3.connect('user_credentials.db')
            cursor = conn.cursor()
                    # Insert user into the database
            cursor.execute('''
                INSERT INTO users (username, password_hash, public_key)
                VALUES (?, ?, ?)
                ''', (username, password_hashed, public_key_pem))
    
            # Commit the changes
            conn.commit()
            conn.close()
            self.accept()
            
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "An Error Occured")
