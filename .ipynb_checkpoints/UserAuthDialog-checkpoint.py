from datetime import datetime
from PyQt5.QtWidgets import (
    QDialog, QLabel, QLineEdit, QVBoxLayout, QMessageBox, QPushButton, QComboBox
)
import sqlite3
from hashlib import sha256
import os
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, b64encode
import secrets

class userAuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Please Input Credentials")
        self.setGeometry(150, 150, 300, 250)  # Adjust size to fit all widgets

        # Username and password inputs
        self.username_label = QLabel("Username:", self)
        self.username_input = QLineEdit(self)

        self.password_label = QLabel("Password:", self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)

        # Reason dropdown
        self.reason_label = QLabel("Reason:", self)
        self.reason_dropdown = QComboBox(self)
        self.reason_dropdown.addItems(["User Login", "File Created", "File Loaded", "New User Created", "Study Completed", "Data Reviewed"])

        # Login button
        self.login_button = QPushButton("Sign", self)
        self.login_button.clicked.connect(self.handle_login)

        # Layout setup
        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.reason_label)
        layout.addWidget(self.reason_dropdown)
        layout.addWidget(self.login_button)
        self.setLayout(layout)

        # Set up logging for audit trail
        logging.basicConfig(filename='audit.log', level=logging.INFO, format='%(asctime)s - %(message)s')

        # Limit login attempts
        self.login_attempts = 0
        self.max_attempts = 3

    def handle_login(self):
        # Get the username and password from input fields
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password cannot be empty.")
            return

        # Increment login attempts
        self.login_attempts += 1

        try:
            # Fetch the salt for the user from the database
            conn = sqlite3.connect('user_credentials.db')
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if not result:
                QMessageBox.warning(self, "Error", "Invalid username or password")
                self.password_input.clear()
                conn.close()
                return

            salt = result[0]

            # Hash the password using the retrieved salt
            password_hash = self.hash_password(password, salt)

            # Verify credentials
            cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
            user = cursor.fetchone()
            conn.close()

            if user:
                logging.info(f"User {username} logged in successfully.")
                QMessageBox.information(self, "Success", f"Welcome, {username}!")
                self.accept()
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                QMessageBox.warning(self, "Error", "Invalid username or password")
                self.password_input.clear()

                # Check if maximum login attempts reached
                if self.login_attempts >= self.max_attempts:
                    QMessageBox.critical(self, "Error", "Maximum login attempts reached. Please try again later.")
                    self.reject()

        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            QMessageBox.critical(self, "Database Error", "An error occurred while accessing the database.")

    def hash_password(self, password, salt):
        # Use PBKDF2HMAC to hash the password with the provided salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
            backend=default_backend()
        )
        return urlsafe_b64encode(kdf.derive(password.encode())).decode()
