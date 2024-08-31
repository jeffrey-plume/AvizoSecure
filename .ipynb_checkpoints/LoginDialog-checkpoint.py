from PyQt5 import QtWidgets
from PyQt5.QtWidgets import (
    QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpinBox, QAction, QMainWindow, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem, QWidget, QGroupBox, QCheckBox
)
import pandas as pd
import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(LoginDialog, self).__init__(parent)


        self.setWindowTitle("Please Input Credentials")
        self.setGeometry(150, 150, 300, 200)

        # Username and password inputs
        self.username_label = QtWidgets.QLabel("Username:", self)
        self.username_input = QtWidgets.QLineEdit(self)

        self.password_label = QtWidgets.QLabel("Password:", self)
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        # Login button
        self.login_button = QtWidgets.QPushButton("Apply", self)
        self.login_button.clicked.connect(self.handle_login)

        # Layout setup
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        self.setLayout(layout)

    def handle_login(self):
        # Get username and password
        username = self.username_input.text()
        password = self.password_input.text()

        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Check credentials in the database
        if self.verify_credentials(username, password_hash):
            self.current_user = username
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid username or password")

    def verify_credentials(self, username, password_hash):
        # Connect to the SQLite database
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()

        # Query to check if the username and password hash match
        cursor.execute('''
        SELECT * FROM users WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        result = cursor.fetchone()

        # Close the connection
        conn.close()

        # If a matching record is found, return True
        return result is not None