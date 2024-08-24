import sys
from PyQt5 import QtWidgets, QtGui
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Avizo Login")
        self.setGeometry(100, 100, 400, 300)

        # Create a button to open the login dialog
        self.login_button = QtWidgets.QPushButton("Login", self)
        self.login_button.setGeometry(150, 130, 100, 40)
        self.login_button.clicked.connect(self.open_login_dialog)

    def open_login_dialog(self):
        # Open the login dialog
        self.login_dialog = LoginDialog(self)
        self.login_dialog.exec_()


class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(LoginDialog, self).__init__(parent)

        self.setWindowTitle("Login")
        self.setGeometry(150, 150, 300, 200)

        # Username and password inputs
        self.username_label = QtWidgets.QLabel("Username:", self)
        self.username_input = QtWidgets.QLineEdit(self)

        self.password_label = QtWidgets.QLabel("Password:", self)
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        # Login button
        self.login_button = QtWidgets.QPushButton("Login", self)
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

        # Hash the password for secure storage
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Simulate retrieval of the stored public key (In a real app, retrieve from the database)
        public_key_pem = self.get_stored_public_key(username)

        # Simulate retrieval of the stored signature (In a real app, retrieve from the database)
        stored_signature = self.get_stored_signature(username)

        # Verify the signature
        if self.verify_signature(public_key_pem, password_hash, stored_signature):
            QtWidgets.QMessageBox.information(self, "Success", "Login Successful!")
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid username or password")

    def get_stored_public_key(self, username):
        # Dummy function to simulate retrieving the stored public key
        # In a real application, retrieve the public key from a database
        return """-----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----"""

    def get_stored_signature(self, username):
        # Dummy function to simulate retrieving the stored signature
        # In a real application, retrieve the signature from a database
        return b"..."

    def verify_signature(self, public_key_pem, password_hash, signature):
        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Verify the signature
        try:
            public_key.verify(
                signature,
                password_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(LoginDialog, self).__init__(parent)

        self.setWindowTitle("Login")
        self.setGeometry(150, 150, 300, 200)

        # Username and password inputs
        self.username_label = QtWidgets.QLabel("Username:", self)
        self.username_input = QtWidgets.QLineEdit(self)

        self.password_label = QtWidgets.QLabel("Password:", self)
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        # Login button
        self.login_button = QtWidgets.QPushButton("Login", self)
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

        # Hash the password for secure storage
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Simulate retrieval of the stored public key (In a real app, retrieve from the database)
        public_key_pem = self.get_stored_public_key(username)

        # Simulate retrieval of the stored signature (In a real app, retrieve from the database)
        stored_signature = self.get_stored_signature(username)

        # Verify the signature
        if self.verify_signature(public_key_pem, password_hash, stored_signature):
            QtWidgets.QMessageBox.information(self, "Success", "Login Successful!")
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid username or password")

    def get_stored_public_key(self, username):
        # Dummy function to simulate retrieving the stored public key
        # In a real application, retrieve the public key from a database
        return """-----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----"""

    def get_stored_signature(self, username):
        # Dummy function to simulate retrieving the stored signature
        # In a real application, retrieve the signature from a database
        return b"..."

    def verify_signature(self, public_key_pem, password_hash, signature):
        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Verify the signature
        try:
            public_key.verify(
                signature,
                password_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

def main():
    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
