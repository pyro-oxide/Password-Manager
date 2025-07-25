# Secure Password Manager

A secure and user-friendly password manager built with Python and Tkinter.

## Features

- Secure password encryption using Fernet (symmetric encryption)
- Master password protection with PBKDF2 key derivation
- Password strength checking using zxcvbn
- Search and sort functionality
- Password categories and notes
- Password generation
- Copy to clipboard functionality
- Modern and intuitive GUI
- Proper error handling and logging

## Security Features

- Passwords are encrypted using Fernet symmetric encryption
- Master password is hashed using PBKDF2 with a random salt
- No plaintext passwords are stored
- Automatic clipboard clearing
- Password strength evaluation
- Reused password detection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python Main.py
```

2. On first run:
   - You'll be prompted to create a master password
   - Choose a strong master password as it protects all your other passwords
   - The master password cannot be recovered if lost

3. Regular use:
   - Enter your master password to unlock the password manager
   - Use the "+" button to add new passwords
   - Use the search bar to find passwords
   - Right-click entries for additional options
   - Use the "Generate Password" button to create strong passwords

## Configuration

- Email settings for OTP can be configured in `config.py`
- Logging settings can be adjusted in `utils.py`
- Database location and other settings can be modified in `config.py`

## Security Recommendations

1. Choose a strong master password
2. Regularly backup your password database
3. Keep your master password safe
4. Don't share your password database
5. Keep your system and Python packages up to date

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 