import sys
from os import listdir, path
import sqlite3
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QDialog, QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpinBox, QAction, QMainWindow, QComboBox, QTabWidget, QTableWidget, 
    QTableWidgetItem, QWidget, QGroupBox, QCheckBox, QMessageBox, QPushButton
)
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np
from skimage.io import imread
from skimage.color import label2rgb
from skimage.measure import label,regionprops
from skimage.morphology import remove_small_objects
from cryptography.hazmat.primitives import serialization, hashes
from LoginDialog import LoginDialog
from RegisterDialog import RegisterDialog
import h5py
from hashlib import sha256 
import logging
from UserAuthDialog import userAuthDialog
# Set up basic configuration for logging
logging.basicConfig(level=logging.INFO, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.unsaved_changes = True
        
        self.setWindowTitle("AvizoSecure")
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
        self.create_results_tab()
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
        self.new_study_action = QAction("New", self)
        self.new_study_action.triggered.connect(self.create_new_study)
        self.new_study_action.setDisabled(True)
        file_menu.addAction(self.new_study_action)

        self.load_study_action = QAction("Open", self)
        self.load_study_action.triggered.connect(self.select_study_file)
        self.load_study_action.setDisabled(True)
        file_menu.addAction(self.load_study_action)

        file_menu.addSeparator()

        self.save_study_action = QAction("Save", self)
        self.save_study_action.triggered.connect(self.save_changes)
        self.save_study_action.setDisabled(True)
        file_menu.addAction(self.save_study_action)

        self.saveas_study_action = QAction("Save As", self)
        self.saveas_study_action.triggered.connect(self.show_save_file_dialog)
        self.saveas_study_action.setDisabled(True)
        file_menu.addAction(self.saveas_study_action)
        
        file_menu.addSeparator()

        # Add Load Images action
        self.load_images_action = QAction("Import Images", self)
        self.load_images_action.triggered.connect(self.select_image_files)
        self.load_images_action.setDisabled(True)
        file_menu.addAction(self.load_images_action)

        # Add Sign action
        self.sign_action = QAction("Sign", self)
        self.sign_action.triggered.connect(self.open_login_dialog)
        self.sign_action.setDisabled(True)
        file_menu.addAction(self.sign_action)

        file_menu.addSeparator()
        
        # Add Sign action
        register = QAction("New User", self)
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
        self.run_recipe_button = QPushButton("Run")
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


        self.checkbox_option1.stateChanged.connect(self.update_display)
        self.checkbox_option2.stateChanged.connect(self.update_display)
        
        side_layout.addStretch()
        # Add the side panel to the main layout
        main_layout.addWidget(side_panel)

    def create_new_study(self):

        # Open a file dialog to create a new file with the .avzo extension
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Create New Study", "", "Avizo Secure Files (*.avzo);;All Files (*)", options=options)
        
        if file_path:
            # Ensure the file has the correct extension
            if not file_path.endswith('.avzo'):
                file_path += '.avzo'
            self.file_path = file_path

            try:
                self.connecttosql(file_path = self.file_path)

                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM audit_trail")
                cursor.execute("DELETE FROM  results")
                self.log_audit_trail(action = 'New Study Created', signature = self.signature)
                            
                self.load_results_table()
                QMessageBox.information(self, 'Success', f'New study created: {file_path}')
            except sqlite3.Error as e:
                QMessageBox.critical(self, 'Error', f'Failed to create database: {e}')  
            # Initialize an SQLite database in the new file




    def connecttosql(self, file_path):
        try:
            with sqlite3.connect(file_path) as conn:
                cursor = conn.cursor()
                # Use context manager to automatically close cursor
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username INTEGER NOT NULL,
                    date TEXT NOT NULL,
                    time TEXT NOT NULL,
                    action TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
                ''')
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    image TEXT NOT NULL,
                    area TEXT NOT NULL,
                    perimeter TEXT NOT NULL,
                    x TEXT NOT NULL,
                    y TEXT NOT NULL,
                    eccentricity TEXT NOT NULL,
                    major_axis_length TEXT NOT NULL,
                    minor_axis_length TEXT NOT NULL
                )
                ''')
    
                self.conn = conn
                self.current_image_index = 0
                self.segment = 0
                self.load_images_action.setDisabled(False)
                self.sign_action.setDisabled(False)
                self.run_recipe_button.setEnabled(True)
                self.save_study_action.setDisabled(False)
                self.saveas_study_action.setDisabled(False)
                self.load_results_table()
    
                logging.info(f"Connected to database: {file_path}")
        except sqlite3.Error as e:
            logging.error(f"Failed to connect to database: {e}")
            QMessageBox.critical(self, 'Error', f'Failed to connect to database: {e}')

                
    # Create the audit_trail table if it doesn't exist
    

    def closeEvent(self, event):
        # Override the closeEvent method to handle application close action
        if self.unsaved_changes:
            reply = QMessageBox.question(self, 'Unsaved Changes',
                                         "You have unsaved changes. Do you want to save them before exiting?",
                                         QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)

            if reply == QMessageBox.Save:
                self.save_changes()
                self.cleanup()
                event.accept()
            elif reply == QMessageBox.Discard:
                self.cleanup()
                event.accept()
            else:
                event.ignore()  # Cancel close
        else:
            self.cleanup()
            event.accept()

    def save_changes(self):

        if self.file_path:
            # Function to recursively save nested dictionary to HDF5
            def save_dict_to_hdf5(data_dict, h5_group):
                for key, value in data_dict.items():
                    if isinstance(value, dict):
                        # If the value is a dictionary, create a group
                        subgroup = h5_group.create_group(str(key))
                        save_dict_to_hdf5(value, subgroup)
                    else:
                        # Otherwise, save the array
                        h5_group.create_dataset(str(key), data=value)
            try:
                # Save nested dictionary to HDF5 file
                with h5py.File(self.file_path.replace("avzo","avzodata"), 'w') as h5f:
                    save_dict_to_hdf5(self.processed_images, h5f)

                
                # Function to recursively load nested dictionary from HDF5
                self.log_audit_trail(action = "Changes Saved")

                self.conn.commit()
                self.unsaved_changes = False
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            self.show_save_file_dialog()

    def cleanup(self):
        # Method to clean up resources (e.g., close database connection)
        if self.conn:
            self.log_audit_trail(action = "Connection Closed")
            self.conn.commit()
            self.conn.close()
            self.conn = None
            
        
    def handle_spin_change(self):
        # Placeholder method to handle spin button changes
        self.log_audit_trail(action = f'Theshold set to : {self.spin_button_1.value()} at image {self.current_image_index}')
        
    def update_display(self):
        
        if self.checkbox_option1.isChecked() and self.checkbox_option2.isChecked():
            self.segment = 3
        elif self.checkbox_option1.isChecked():
            self.segment = 1
        elif self.checkbox_option2.isChecked():
            self.segment = 2
        else:
            self.segment = 0

        self.display_image(self.current_image_index)

    def create_image_tab(self):
        # Tab for image display and controls
        image_tab = QWidget()
        self.tabs.addTab(image_tab, "Image Display")

        # Layout for the tab
        layout = QVBoxLayout(image_tab)

        # Image display area
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setFixedSize(720, 720)

        layout.addWidget(self.canvas)

    def create_results_tab(self):
        # Tab for image display and controls
        results_tab = QWidget()
        self.tabs.addTab(results_tab, "Results")

        # Layout for the tab
        layout = QVBoxLayout(results_tab)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels(["image", "area", "perimeter", "x", "y", "eccentricity", "major_axis_length", "minor_axis_length"])

        # Add table to the layout
        layout.addWidget(self.results_table)

    def create_audit_trail_tab(self):
        # Tab for displaying audit trail (timestamped table of actions)
        audit_trail_tab = QWidget()
        self.tabs.addTab(audit_trail_tab, "Audit Trail")

        # Layout for the tab
        layout = QVBoxLayout(audit_trail_tab)

        # Create table widget
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels(["Username", "Date", "Time", "Action", "Signature"])

        # Add table to the layout
        layout.addWidget(self.audit_table)

    def load_audit_trail_data(self):

        cursor = self.conn.cursor()
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


    def load_results_table(self):

        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT image, area, perimeter, x, y, eccentricity, major_axis_length, minor_axis_length FROM results WHERE image = (?)", (self.current_image_index,))
                dataRecord = cursor.fetchall()

                self.results_table.setRowCount(len(dataRecord))
        
                # Populate table with data
                for row_index, (image, area, perimeter, x, y, eccentricity, major_axis_length, minor_axis_length) in enumerate(dataRecord):
                    #date, time = time_stamp.split(" ")
                    self.results_table.setItem(row_index, 0, QTableWidgetItem(image))
                    self.results_table.setItem(row_index, 1, QTableWidgetItem(area))
                    self.results_table.setItem(row_index, 2, QTableWidgetItem(perimeter))
                    self.results_table.setItem(row_index, 3, QTableWidgetItem(x))
                    self.results_table.setItem(row_index, 4, QTableWidgetItem(y))
                    self.results_table.setItem(row_index, 5, QTableWidgetItem(eccentricity))
                    self.results_table.setItem(row_index, 6, QTableWidgetItem(major_axis_length))
                    self.results_table.setItem(row_index, 7, QTableWidgetItem(minor_axis_length))
                    
            except Exception as e:
                
                QMessageBox.warning(self, "Error", f"An error occurred: {e}")

    def open_login_dialog(self):
        # Open the login dialog
        self.login_dialog = LoginDialog(self)
        if self.login_dialog.exec_() == QDialog.Accepted:
            # Set the current user
            self.signature = self.login_dialog.info 
            self.current_user = self.login_dialog.current_user            
            self.new_study_action.setDisabled(False)
            self.load_study_action.setDisabled(False)
            self.log_audit_trail(action=self.login_dialog.action, signature = self.signature)
                
    def select_image_files(self):
        # Open a file dialog to select multiple image files
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, 
            "Select Image Files", 
            "", 
            "Images (*.png *.jpg *.jpeg *.tiff *.tif);;All Files (*)"
        )
        
        if file_paths:
            self.image_files = file_paths  # Store the selected file paths
            self.image_files.sort()  # Sort files alphabetically (optional)
            self.processed_images = {}
            self.segment = 0
    
            if self.image_files:
                self.image_spinbox.setMaximum(len(self.image_files) - 1)
                self.current_image_index = 0
                self.display_image(self.current_image_index)
                self.log_audit_trail(action=f'Images loaded from selected files: {file_paths}')
            else:
                QMessageBox.warning(self, "Error", "No images selected.")
        else:
            QMessageBox.warning(self, "Error", "No files were selected.")

    def select_study_file(self):
        # Open a file dialog and get the selected file path
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Avizo Secure (*avzo);;Text Files (*.avzo)", options=options)
        if file_path:
            self.file_path = file_path

            try:
                self.connecttosql(file_path=self.file_path)

                def load_dict_from_hdf5(h5_group):
                    data_dict = {}
                    for key, item in h5_group.items():
                        if isinstance(item, h5py.Group):
                            data_dict[int(key)] = load_dict_from_hdf5(item)
                        else:
                            data_dict[int(key)] = item[()]
                    return data_dict
            
                # Load nested dictionary back from HDF5 file
                with h5py.File(file_path.replace('avzo', 'avzodata'), 'r') as h5f:
                    self.processed_images = load_dict_from_hdf5(h5f)
                    
                self.image_spinbox.setMaximum(len(self.processed_images) - 1)
                
                self.display_image(index = 0)
                self.log_audit_trail(action = f'{file_path} loaded', signature = self.signature)
                QMessageBox.information(self, "Load Study", "Study Loaded Sucessfully.")

            except Exception as e:
                QMessageBox.warning(self, "Error", f"An error occurred: {e}")
            
            
        else:
            QMessageBox.warning(self, "Error", "Load error.")
            
    def show_save_file_dialog(self):
        # Open a save file dialog and get the file path to save
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_path:
            self.file_path = file_path
            self.save_changes()
    
    def display_image(self, index):
        self.current_image_index = index
        if hasattr(self, 'processed_images'):

            if not self.current_image_index in self.processed_images.keys():
                # Read and process the image
                image_path = self.image_files[index]
                orig = imread(image_path)
                orig = ((orig - orig.min()) / orig.max()) * 255
                self.processed_images[self.current_image_index] = {i: orig.astype(np.uint8) for i in range(4)}
    
            # Update the display
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            ax.imshow(self.processed_images[self.current_image_index][self.segment], cmap='gray')
            ax.axis('off')
            self.load_results_table()
            self.canvas.draw()
        else:
            QMessageBox.warning(self, "Error", "No images available to display.")

    def run_avizo_recipe(self):
        if hasattr(self, 'processed_images'):
            try:
                index = self.current_image_index
                processed = self.processed_images[self.current_image_index]
                threshold_value = (self.spin_button_1.value() / 100) * processed[0].max()
                binary_image = processed[0] > threshold_value
                labeled_image = label(binary_image)
                regions = regionprops(labeled_image)
    
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM results WHERE image = ?', (str(index),))
    
                for region in regions:
                    cursor.execute('''
                        INSERT INTO results (image, area, perimeter, x, y, eccentricity, major_axis_length, minor_axis_length)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (str(index), region.area, region.perimeter, region.centroid[0], region.centroid[1],
                          region.eccentricity, region.major_axis_length, region.minor_axis_length))
    
                self.conn.commit()
    
                colored_image = label2rgb(labeled_image)
                self.processed_images[self.current_image_index][3] = label2rgb(labeled_image)
                large_objects = remove_small_objects(labeled_image, min_size=100)
                self.processed_images[self.current_image_index][1] = label2rgb(large_objects)
                small = labeled_image ^ large_objects
                self.processed_images[self.current_image_index][2] = label2rgb(small)
    
                self.display_image(self.current_image_index)
                self.segment = 3
                self.display_image(self.current_image_index)
                self.checkbox_option1.setChecked(True)
                self.checkbox_option2.setChecked(True)
    
                self.log_audit_trail(action=f"Analyzed image {self.current_image_index}. Threshold: {self.spin_button_1}%.")
                QMessageBox.information(self, "Success", "Thresholding and labeling performed successfully.")
                self.unsaved_changes = True
                logging.info(f"Image {index} analyzed successfully.")
            except Exception as e:
                logging.error(f"Error during image processing: {e}")
                QMessageBox.warning(self, "Error", f"An error occurred during image processing: {e}")
        else:
            QMessageBox.warning(self, "Error", "No image loaded or image path is invalid.")



    def log_audit_trail(self, action, signature = ""):

        if hasattr(self, 'conn'):
        # Connect to the SQLite database
            cursor = self.conn.cursor()
    
            # Insert the audit trail log into the audit_trail table
            date = datetime.now().strftime("%Y-%m-%d")
            time = datetime.now().strftime("%H:%M:%S")
            cursor.execute('''
            INSERT INTO audit_trail (username, date, time, action, signature)
            VALUES (?, ?, ?, ?, ?)
            ''', (self.current_user, date, time, action, signature))
            self.load_audit_trail_data()

    def register_action(self):
        # Instantiate the registration dialog using the registerDialog class
        self.RegisterDialog = RegisterDialog(self)
        
        # Execute the dialog and check if the user clicked "Register" and was successful
        if self.RegisterDialog.exec_() == QDialog.Accepted:
            # Set the current user based on the username input from the registration dialog
            self.current_user = self.RegisterDialog.username_input.text().strip()
            logging.info(f'User registered successfully: {self.current_user}')
        else:
            logging.warning('Registration was not completed.')
    

class FileDialog(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Open file dialog to select multiple files
        file_names, _ = QFileDialog.getOpenFileNames(self, "Open Files", "", "All Files (*);;Text Files (*.txt);;Images (*.png *.xpm *.jpg)")
        if file_names:
            print(f"Selected files: {file_names}")

def main():
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()