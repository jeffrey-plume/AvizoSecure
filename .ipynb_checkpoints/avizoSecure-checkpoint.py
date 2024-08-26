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
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np
from skimage import io, color, measure, morphology

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Avizo Application with Tabs and Side Panel")
        self.setGeometry(100, 100, 800, 600)

        # Create a central widget to hold everything
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create a main layout
        main_layout = QHBoxLayout(central_widget)

        # Create side panel with two spin buttons
        self.create_side_panel(main_layout)

        # Create tab widget for main content
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Create tabs
        self.create_image_tab()
        self.create_audit_trail_tab()

        # Set up menu bar
        self.create_menu_bar()

        # Current logged-in user
        self.current_user = None
        self.processed_images = {}
        
    def create_menu_bar(self):
        # Create a menu bar
        menu_bar = self.menuBar()

        # Create File menu
        file_menu = menu_bar.addMenu("File")

        # Add Login action
        login_action = QAction("Login", self)
        login_action.triggered.connect(self.open_login_dialog)
        file_menu.addAction(login_action)
        
        file_menu.addSeparator()

        # Add Load Images action
        self.load_images_action = QAction("Load Images", self)
        self.load_images_action.triggered.connect(self.select_image_folder)
        self.load_images_action.setDisabled(True)
        file_menu.addAction(self.load_images_action)

        # Add Sign action
        self.sign_action = QAction("Sign", self)
        self.sign_action.triggered.connect(self.open_sign_dialog)
        self.sign_action.setDisabled(True)
        file_menu.addAction(self.sign_action)

        file_menu.addSeparator()
        
        # Add Sign action
        register = QAction("User Register", self)
        register.triggered.connect(self.register_action)
        file_menu.addAction(register)

        file_menu.addSeparator()
        # Add Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def create_side_panel(self, main_layout):
        # Create a side panel widget
        side_panel = QWidget()
        side_layout = QVBoxLayout(side_panel)

                # Spinbox to navigate through images
        self.image_spinbox = QSpinBox()
        self.image_spinbox.valueChanged.connect(self.display_image)

        # Add two spin buttons to the side panel
        self.spin_button_1 = QSpinBox()
        self.spin_button_1.setValue(20)
        self.spin_button_1.setRange(0, 100)
        self.spin_button_1.valueChanged.connect(self.handle_spin_change)
        
        # Command button to trigger Avizo recipe
        self.run_recipe_button = QtWidgets.QPushButton("Run")
        self.run_recipe_button.clicked.connect(self.run_avizo_recipe)
        self.run_recipe_button.setEnabled(False)

        checkbox_group = QGroupBox("Visible")
        checkbox_layout = QVBoxLayout()

        
        self.checkbox_option1 = QCheckBox("Nuclei")
        self.checkbox_option2 = QCheckBox("Micronuclei")
        checkbox_layout.addWidget(self.checkbox_option1)
        checkbox_layout.addWidget(self.checkbox_option2)
        checkbox_group.setLayout(checkbox_layout)

        # Add spin buttons to the side panel layout
        side_layout.addWidget(QLabel("Image Number"))
        side_layout.addWidget(self.image_spinbox)
        side_layout.addWidget(QLabel("Threshold"))
        side_layout.addWidget(self.spin_button_1)
        side_layout.addWidget(QLabel("Execute"))
        side_layout.addWidget(self.run_recipe_button)
        # Add the checkbox group to the side panel layout
        side_layout.addWidget(checkbox_group)
        
        side_layout.addStretch()
        # Add the side panel to the main layout
        main_layout.addWidget(side_panel)


    def handle_spin_change(self):
        # Placeholder method to handle spin button changes
        spin1_value = self.spin_button_1.value()
        spin2_value = self.spin_button_2.value()


    def create_image_tab(self):
        # Tab for image display and controls
        image_tab = QtWidgets.QWidget()
        self.tabs.addTab(image_tab, "Image Display")

        # Layout for the tab
        layout = QVBoxLayout(image_tab)

        # Image display area
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setFixedSize(720, 720)

        layout.addWidget(self.canvas)



    def create_audit_trail_tab(self):
        # Tab for displaying audit trail (timestamped table of actions)
        audit_trail_tab = QtWidgets.QWidget()
        self.tabs.addTab(audit_trail_tab, "Audit Trail")

        # Layout for the tab
        layout = QVBoxLayout(audit_trail_tab)

        # Create table widget
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels(["Username", "Date", "Time", "Action", "Signature"])
        self.load_audit_trail_data()  # Load initial data

        # Add table to the layout
        layout.addWidget(self.audit_table)

    def load_audit_trail_data(self):
        # Load data from the audit trail table and populate the QTableWidget
        conn = sqlite3.connect('audit.db')
        cursor = conn.cursor()

                # Create the audit_trail table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            action TEXT NOT NULL,
            signature TEXT NOT NULL
        )
        ''')
        # Query to get all audit logs
        cursor.execute("SELECT username, Date, Time, action, signature FROM audit_trail")
        logs = cursor.fetchall()

        # Set row count
        self.audit_table.setRowCount(len(logs))

        # Populate table with data
        for row_index, (username, date, time, action, signature) in enumerate(logs):
            #date, time = time_stamp.split(" ")
            self.audit_table.setItem(row_index, 0, QTableWidgetItem(username))
            self.audit_table.setItem(row_index, 1, QTableWidgetItem(date))
            self.audit_table.setItem(row_index, 2, QTableWidgetItem(time))
            self.audit_table.setItem(row_index, 3, QTableWidgetItem(action))
            self.audit_table.setItem(row_index, 4, QTableWidgetItem(signature))

        conn.close()

    def open_login_dialog(self):
        # Open the login dialog
        self.login_dialog = LoginDialog(self)
        if self.login_dialog.exec_() == QtWidgets.QDialog.Accepted:
            # Set the current user
            self.current_user = self.login_dialog.current_user
            # Reload audit trail data to update the table
            self.log_audit_trail(action = "User login")
            self.load_images_action.setDisabled(False)
            self.sign_action.setDisabled(False)
            self.load_audit_trail_data()
            self.run_recipe_button.setEnabled(True)
            QtWidgets.QMessageBox.information(self, "Login", "Login Successful.")
            
    def open_sign_dialog(self):
        # Open the login dialog
        self.sign_dialog = LoginDialog(self)
        if self.sign_dialog.exec_() == QtWidgets.QDialog.Accepted:
            conn = sqlite3.connect('user_credentials.db')
            cursor = conn.cursor()
            cursor.execute("SELECT public_key FROM users WHERE username = ?", (self.current_user,))
            result = cursor.fetchone()
            conn.close()

            if result:
                public_key_pem = result[0]
                public_key = serialization.load_pem_public_key(
                    public_key_pem,
                    backend=default_backend()
                )

                # Generate a digital signature (simulated here)
                message = f"User {self.current_user} performed a sign action. {datetime.now()}"
                signature = hashlib.sha256(message.encode()).hexdigest()

                # Log the signature in the audit trail
                self.log_audit_trail(action = f'Signed by {self.current_user}', signature=signature)
                
                self.load_audit_trail_data()
                QtWidgets.QMessageBox.information(self, "Signature", "Digital signature created and logged.")
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Public key not found for the current user.")
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "No user is currently logged in.")
            
    def select_image_folder(self):
       # Open a file dialog to select a folder containing images
        folder_path = QFileDialog.getExistingDirectory(self, "Select Image Folder", "")
        if folder_path:
            self.selected_image_folder = folder_path
            self.image_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)
                                if f.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.tif'))]
            self.image_files.sort()  # Sort files alphabetically
        
            if self.image_files:
                self.image_spinbox.setMaximum(len(self.image_files) - 1)
                self.current_image_index = 0
                self.display_image(self.current_image_index)
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "No images found in the selected folder.")

    def display_image(self, index):
        if hasattr(self, 'image_files') and self.image_files:
            self.current_image_index = index
            image_path = self.image_files[self.current_image_index]

            if image_path in self.processed_images:
                # Display the processed image using matplotlib

                if self.checkbox_option1 == True and self.checkbox_option2 == False:
                    processed_image = self.processed_images[image_path][1]
                elif  self.checkbox_option2 == True and self.checkbox_option1 == False:
                    processed_image = self.processed_images[image_path][2]
                else:
                    processed_image = self.processed_images[image_path][0]
                
                
                self.figure.clear()
                ax = self.figure.add_subplot(111)
                ax.imshow(processed_image)
                ax.axis('off')
                self.canvas.draw()
            else:
                # Display the original image using matplotlib
                image = io.imread(image_path)
                mn = image.min()
                mx = image.max()                
                mx -= mn                
                image = ((image - mn)/mx) * 255
                self.figure.clear()
                ax = self.figure.add_subplot(111)
                ax.imshow(image.astype(np.uint8), cmap='gray')
                ax.axis('off')
                self.canvas.draw()

    def run_avizo_recipe(self):
        # Perform thresholding on the current image and store the result
        if hasattr(self, 'image_files') and self.image_files:
            image_path = self.image_files[self.current_image_index]
            image = io.imread(image_path, as_gray=True)  # Load image in grayscale
            mn = image.min()
            mx = image.max() 
            mx -= mn      
            image = ((image - mn)/mx) * 255
            image = image.astype(np.uint8)
            # Get threshold value from spin button 1
            threshold_value = (self.spin_button_1.value() /100) * image.max()
            binary_image = image > threshold_value

                
            # Label connected components
            labeled_image = measure.label(binary_image)
            large_objects = morphology.remove_small_objects(labeled_image, min_size=100)
            small_objects = labeled_image ^ large_objects
            
            if self.checkbox_option1 == True and self.checkbox_option2 == False:
                labeled_image_colored = color.label2rgb(large_objects, bg_label=0)
            elif self.checkbox_option2 == True and self.checkbox_option1 == False:
                labeled_image_colored = color.label2rgb(small_objects, bg_label=0)
            elif self.checkbox_option2 == True and self.checkbox_option1 == True:
                 labeled_image_colored = color.label2rgb(labeled_image, bg_label=0)
            else:
                labeled_image_colored = image
                

            # Store the processed image
            self.processed_images[image_path] = labeled_image_colored

            # Display the labeled image using matplotlib
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            ax.imshow(labeled_image_colored)
            ax.axis('off')
            self.canvas.draw()

            QtWidgets.QMessageBox.information(self, "Success", "Thresholding and labeling performed successfully.")
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "No image loaded or image path is invalid.")

            

    def log_audit_trail(self, action, signature = ""):
        # Connect to the SQLite database
        conn = sqlite3.connect('audit.db')
        cursor = conn.cursor()

        # Insert the audit trail log into the audit_trail table
        date = datetime.now().strftime("%Y-%m-%d")
        time = datetime.now().strftime("%H:%M:%S")
        cursor.execute('''
        INSERT INTO audit_trail (username, date, time, action, signature)
        VALUES (?, ?, ?, ?, ?)
        ''', (self.current_user, date, time, action, signature))

        # Commit the transaction and close the connection
        conn.commit()
        conn.close()

    def register_action(self):
        self.registerDialog = registerDialog(self)
        if self.registerDialog.exec_() == QtWidgets.QDialog.Accepted:
            self.current_user = self.registerDialog.current_user
            self.log_audit_trail(action = "User registered")
            self.load_audit_trail_data()
            QtWidgets.QMessageBox.information(self, "Registration", "Registration Successful.")
    
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


def main():
    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()