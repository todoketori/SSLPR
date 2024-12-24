					***Service Secured ReadMe***

(This is a project intended to be a collaborative effort between me and an additional developer)

This script runs a simple encryption app. To use this app you run the script, 
open the file section, press 'Encrypt' and save the encrypted file in the folder of your choosing.
 
NOTE, a password must be generated before a file can be encrypted. 
Once the password is generated and the file is encrypted you must select 'Save To File' 
and save the password in the location of your choosing. 

This will create a .txt file that contains the encryption password.
When the password has been generated & saved and your files are encrypted they are secured.
When you have successfully encrypted your files the checkbox under the 'Encrypted Files' 
button will be checked. 

(You can click the 'Encrypted Files' button to open a window
that displays the path that the encrypted files have been saved to.) 

This script is a Python program that creates a graphical user interface (GUI) application using tkinter. The application is designed to handle file encryption and decryption using the cryptography.fernet module.

When broken down, these are the core functions of this script:

1. Class SecureApp: This class defines the main application. It initializes the GUI components and contains methods for various functionalities.

2. Initialization Method (__init__): This method sets up the main window, its title, and GUI elements like menus, buttons, and a check button. It also initializes some variables.

3. Encryption Functionality (encrypt_file):
Allows the user to select a file.
If a password has been generated, it encrypts the file with Fernet symmetric encryption.

4. Saves the encrypted file to a chosen directory.
Password Generation (generate_password):
Generates a Fernet key (password) and stores it.

5. Decryption Functionality (decrypt_file):

Decrypts a provided encrypted file using the stored password.

6. Saves the decrypted file in a separate directory.
Enter Password and Decrypt (enter_password):

Asks the user to enter the generated password.

7. Calls decrypt_file with the path of the selected file.
Save Password to File (save_to_file):

Saves the generated password to a text file.

8. Admin Login (admin_login):

Placeholder for admin login functionality.

9. Close Application (close_app):

Closes the application window.
Custom Settings (custom_settings):

10. Placeholder function for custom settings, including a dialog to select a directory and create a new window with custom settings.

11. Show Encrypted Files (show_encrypted_files):

Displays a list of encrypted files in a new window.

Main Section:

This part initializes the tkinter root and starts the application loop.
