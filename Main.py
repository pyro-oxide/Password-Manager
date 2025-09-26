import sys
import logging
import time
import random
import string
from typing import Optional, Dict, Any, List

# Use PyQt5 if available, otherwise fall back or notify
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
        QSplitter, QFrame, QTabWidget, QGridLayout, QAction, QMenu,
        QSystemTrayIcon, QStyle, QToolBar, QStatusBar, QScrollArea,
        QStackedWidget, QGroupBox, QMessageBox, QDialog, QDialogButtonBox,
        QComboBox, QFormLayout, QTextEdit, QCheckBox, QFileDialog, QProgressDialog,
        QInputDialog, QSizePolicy, QSpacerItem, QSpinBox, QRadioButton, QButtonGroup
    )
    from PyQt5.QtCore import Qt, QSize, QTimer, QEvent, pyqtSignal, QThread, QSettings, QUrl
    from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QMouseEvent, QDesktopServices, QImage, QPainter
    import qtawesome as qta  # For icons: pip install qtawesome
except ImportError:
    print("PyQt5 or qtawesome not found. Please install them: pip install PyQt5 qtawesome")
    sys.exit(1)

# Use pyperclip if available
try:
    import pyperclip
except ImportError:
    print("pyperclip not found. Clipboard functions will be disabled. Install with: pip install pyperclip")
    pyperclip = None  # Define it as None to check later

from utils import (
    setup_logging, hash_password, verify_password, generate_encryption_key_from_password,
    encrypt_data, decrypt_data, Fernet, InvalidToken, check_password_strength,
    generate_password, export_vault, import_vault, copy_to_clipboard_timed,
    generate_totp_secret, get_totp_uri, verify_totp_code, generate_qr_code_image,
    send_otp_email
)
from config import (
    APP_NAME, APP_VERSION, DB_PATH, DB_BACKUP_PATH, AUTO_LOCK_TIMEOUT_MINUTES,
    CLIPBOARD_CLEAR_TIMEOUT_SECONDS, TOTP_ISSUER_NAME, ICON_PATH,
    LOG_PATH)
from database import DatabaseManager

# --- Setup Logging ---
setup_logging()
log = logging.getLogger(__name__)


# --- Password Entry Item Widget ---
class PasswordListItemWidget(QWidget):
    def __init__(self, entry_id: int, site: str, username: str, category: str, parent=None):
        super().__init__(parent)
        self.entry_id = entry_id
        self.site = site
        self.username = username
        self.category = category
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        
        # Site icon
        icon_label = QLabel()
        try:
            icon_label.setPixmap(qta.icon('fa5s.globe', color='#34495e').pixmap(QSize(16, 16)))
        except Exception:
            icon_label.setText("🌐")
        layout.addWidget(icon_label)
        
        # Site name
        site_label = QLabel(site)
        site_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(site_label)
        
        # Username
        username_label = QLabel(username)
        username_label.setStyleSheet("color: gray;")
        layout.addWidget(username_label)
        
        # Category with color
        self.category_label = QLabel(category)
        self.category_label.setStyleSheet("color: gray; padding: 2px 6px; border-radius: 3px;")
        layout.addWidget(self.category_label)
        
        layout.addStretch()
        
        # Set initial category color
        self.set_category_color('#808080')  # Default gray color

    def set_category_color(self, color: str):
        """Set the category label color."""
        self.category_label.setStyleSheet(f"""
            color: {color};
            padding: 2px 6px;
            border-radius: 3px;
            background-color: {color}20;  /* 20 is hex for 12% opacity */
            border: 1px solid {color}40;  /* 40 is hex for 25% opacity */
        """)


# --- Password Input Dialog ---
class PasswordDialog(QDialog):
    def __init__(self, parent=None, prompt="Enter password:", is_confirmation=False, title="Password"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.password = ""
        self.setMinimumWidth(350)
        self.setup_ui(prompt, is_confirmation)
        self.password_edit.setFocus()

    def setup_ui(self, prompt, is_confirmation):
        layout = QVBoxLayout(self)

        # Prompt label
        self.prompt_label = QLabel(prompt)
        layout.addWidget(self.prompt_label)

        # Password input
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_edit)

        if is_confirmation:
            self.confirm_label = QLabel("Confirm password:")
            layout.addWidget(self.confirm_label)
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_edit)
            self.password_edit.textChanged.connect(self.check_match)
            self.confirm_edit.textChanged.connect(self.check_match)

        # Error label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red;")
        layout.addWidget(self.error_label)
        self.error_label.hide()

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept_password)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        # Initially disable OK if confirmation is required and fields are empty
        if is_confirmation:
            self.button_box.button(QDialogButtonBox.Ok).setEnabled(False)

    def check_match(self):
        if hasattr(self, 'confirm_edit'):
            p1 = self.password_edit.text()
            p2 = self.confirm_edit.text()
            match = (p1 == p2) and bool(p1)  # Must match and not be empty
            self.button_box.button(QDialogButtonBox.Ok).setEnabled(match)
            if p1 and p2 and p1 != p2:
                self.error_label.setText("Passwords do not match!")
                self.error_label.show()
            else:
                self.error_label.hide()

    def accept_password(self):
        if hasattr(self, 'confirm_edit'):
            if self.password_edit.text() != self.confirm_edit.text():
                self.error_label.setText("Passwords do not match!")
                self.error_label.show()
                # QMessageBox.warning(self, "Error", "Passwords do not match!")
                return
            if not self.password_edit.text():
                self.error_label.setText("Password cannot be empty!")
                self.error_label.show()
                return

        self.password = self.password_edit.text()
        self.accept()

    def get_password(self):
        return self.password


# --- Add/Edit Password Dialog ---
class AddEditPasswordDialog(QDialog):
    def __init__(self, parent=None, db_manager=None, current_categories=None, entry_data=None):
        super().__init__(parent)
        self.db = db_manager
        self.current_categories = current_categories if current_categories else []
        self.entry_data = entry_data  # Dict with existing data if editing
        self.is_edit_mode = entry_data is not None

        title = "Edit Password" if self.is_edit_mode else "Add New Password"
        self.setWindowTitle(title)
        self.setMinimumWidth(450)
        self.setup_ui()
        if self.is_edit_mode:
            self.populate_fields()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        form_layout.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form_layout.setLabelAlignment(Qt.AlignRight)

        # Site Name
        self.site_edit = QLineEdit()
        form_layout.addRow("Site/App Name:", self.site_edit)

        # Username
        self.username_edit = QLineEdit()
        form_layout.addRow("Username:", self.username_edit)

        # Password
        password_layout = QHBoxLayout()
        password_layout.setContentsMargins(0, 0, 0, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.textChanged.connect(self.update_strength_indicator)
        password_layout.addWidget(self.password_edit)

        show_pass_btn = QPushButton(qta.icon('fa5s.eye'), "")
        show_pass_btn.setToolTip("Show/Hide Password")
        show_pass_btn.setCheckable(True)
        show_pass_btn.toggled.connect(self.toggle_password_visibility_dialog)
        password_layout.addWidget(show_pass_btn)

        generate_btn = QPushButton(qta.icon('fa5s.magic'), "")
        generate_btn.setToolTip("Generate Password")
        generate_btn.clicked.connect(self.open_generate_password_dialog)
        password_layout.addWidget(generate_btn)
        form_layout.addRow("Password:", password_layout)

        # Strength Indicator
        self.strength_bar = QWidget()
        self.strength_bar.setFixedHeight(10)
        self.strength_bar.setAutoFillBackground(True)
        self.strength_layout = QHBoxLayout(self.strength_bar)  # Use a layout inside the widget
        self.strength_layout.setContentsMargins(0, 0, 0, 0)
        self.strength_layout.setSpacing(1)
        self.strength_segments = []
        for _ in range(5):
            segment = QFrame()
            segment.setFrameShape(QFrame.Panel)
            segment.setFrameShadow(QFrame.Sunken)
            self.strength_layout.addWidget(segment)
        form_layout.addRow("", self.strength_bar)  # Add the container widget

        self.strength_label = QLabel("Strength: N/A")
        self.strength_label.setStyleSheet("font-size: 10px; color: gray;")
        form_layout.addRow("", self.strength_label)

        # Website URL
        self.website_edit = QLineEdit()
        self.website_edit.setPlaceholderText("e.g., https://www.example.com")
        form_layout.addRow("Website URL:", self.website_edit)

        # Category
        category_layout = QHBoxLayout()
        category_layout.setContentsMargins(0, 0, 0, 0)
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.addItems(['Uncategorized'] + sorted(self.current_categories))
        self.category_combo.setInsertPolicy(QComboBox.NoInsert)  # Don't automatically add typed items
        from PyQt5.QtWidgets import QCompleter
        self.category_combo.completer().setCompletionMode(QCompleter.InlineCompletion)  # Auto-complete
        category_layout.addWidget(self.category_combo)
        form_layout.addRow("Category:", category_layout)

        # Notes
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(100)
        self.notes_edit.setPlaceholderText("Optional notes...")
        form_layout.addRow("Notes:", self.notes_edit)

        layout.addLayout(form_layout)

        # Duplicate Password Warning
        self.duplicate_warning_label = QLabel("")
        self.duplicate_warning_label.setStyleSheet("color: orange;")
        layout.addWidget(self.duplicate_warning_label)
        self.duplicate_warning_label.hide()

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        # Initial state update
        self.update_strength_indicator()

    def toggle_password_visibility_dialog(self, checked):
        self.password_edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def open_generate_password_dialog(self):
        dialog = GeneratePasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            generated_password = dialog.get_password()
            self.password_edit.setText(generated_password)
            # Briefly show the generated password
            self.password_edit.setEchoMode(QLineEdit.Normal)
            QTimer.singleShot(1500, lambda: self.password_edit.setEchoMode(QLineEdit.Password))

    def update_strength_indicator(self):
        password = self.password_edit.text()
        strength = check_password_strength(password)
        score = strength['score']  # 0-4

        # Update bar color and segments
        colors = ["#FF4136", "#FF851B", "#FFDC00", "#2ECC40", "#0074D9"]  # Red, Orange, Yellow, Green, Blue
        score_desc = strength.get('strength_description', 'N/A')

        for i, segment in enumerate(self.strength_segments):
            p = segment.palette()
            if i <= score:
                p.setColor(segment.backgroundRole(), QColor(colors[i]))
            else:
                # Use the default window background color for inactive segments
                p.setColor(segment.backgroundRole(), self.palette().color(QPalette.Window))
            segment.setPalette(p)
            segment.setAutoFillBackground(True)

        # Update label
        self.strength_label.setText(f"Strength: {score_desc}")
        feedback = strength.get('feedback', {})
        warning = feedback.get('warning')
        suggestions = feedback.get('suggestions', [])
        tooltip_text = score_desc
        if warning:
            tooltip_text += f"\nWarning: {warning}"
        if suggestions:
            tooltip_text += "\nSuggestions:\n- " + "\n- ".join(suggestions)
        self.strength_bar.setToolTip(tooltip_text)
        self.strength_label.setToolTip(tooltip_text)

        # Check for duplicates (if db is available)
        self.check_duplicate_password(password)

    def check_duplicate_password(self, password):
        if not password or not self.db or not hasattr(self.parent(), 'cipher'):
            self.duplicate_warning_label.hide()
            return

        cipher_suite = self.parent().cipher
        if not cipher_suite:
            self.duplicate_warning_label.hide()
            return

        all_encrypted = self.db.get_all_encrypted_passwords()
        is_duplicate = False
        current_entry_id = self.entry_data.get('id') if self.is_edit_mode and self.entry_data else -1

        for enc_password in all_encrypted:
            try:
                decrypted = decrypt_data(enc_password, cipher_suite)
                if decrypted and decrypted.decode('utf-8') == password:
                    is_duplicate = True
                    break
            except Exception as e:
                log.debug(f"Error decrypting a password during duplicate check: {e}")
                continue

        if is_duplicate:
            self.duplicate_warning_label.setText("⚠️ Warning: This password is used elsewhere in your vault.")
            self.duplicate_warning_label.show()
        else:
            self.duplicate_warning_label.hide()

    def populate_fields(self):
        """Fill the dialog fields if in edit mode."""
        if not self.is_edit_mode or not self.entry_data:
            return

        self.site_edit.setText(self.entry_data.get('site', ''))
        self.username_edit.setText(self.entry_data.get('username', ''))

        # Decrypt password for editing
        encrypted_pwd = self.entry_data.get('encrypted_password', '')
        cipher_suite = self.parent().cipher  # Get cipher from main window
        decrypted_pwd = ""
        if encrypted_pwd and cipher_suite:
            dec_bytes = decrypt_data(encrypted_pwd, cipher_suite)
            if dec_bytes:
                decrypted_pwd = dec_bytes.decode('utf-8')
            else:
                # Handle decryption failure (e.g., show error, clear field)
                QMessageBox.warning(self, "Decryption Error",
                                    "Could not decrypt the password. It might be corrupted or saved with a different master key.")

        self.password_edit.setText(decrypted_pwd)
        self.website_edit.setText(self.entry_data.get('website', ''))

        # Set category
        category = self.entry_data.get('category', 'Uncategorized')
        index = self.category_combo.findText(category)
        if index >= 0:
            self.category_combo.setCurrentIndex(index)
        else:
            # If category not in list, add it and select it
            self.category_combo.addItem(category)
            self.category_combo.setCurrentText(category)

        self.notes_edit.setText(self.entry_data.get('notes', ''))
        self.update_strength_indicator()  # Update strength for existing password

    def get_values(self) -> Optional[Dict[str, Any]]:
        """Return the values entered in the dialog."""
        site = self.site_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text()  # Keep original spacing/chars

        if not site or not username or not password:
            QMessageBox.warning(self, "Missing Information", "Site/App Name, Username, and Password are required.")
            return None

        # Get category (handle typed vs selected)
        category = self.category_combo.currentText().strip()
        if not category:
            category = 'Uncategorized'

        return {
            'site': site,
            'username': username,
            'password': password,  # Return plain text password here
            'website': self.website_edit.text().strip(),
            'category': category,
            'notes': self.notes_edit.toPlainText().strip()
        }

    def accept(self):
        """Validate before closing."""
        if self.get_values():  # Validation happens within get_values
            super().accept()


# --- Generate Password Dialog ---
class GeneratePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.generated_password = ""
        self.setup_ui()
        self.update_password()  # Generate initial password

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Password display
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setFont(QFont("Courier", 12))
        layout.addWidget(self.password_display)

        # Regenerate button
        regenerate_btn = QPushButton(qta.icon('fa5s.sync-alt'), " Regenerate")
        regenerate_btn.clicked.connect(self.update_password)
        layout.addWidget(regenerate_btn)

        # Options GroupBox
        options_group = QGroupBox("Options")
        options_layout = QFormLayout(options_group)

        # Length
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(8, 128)
        self.length_spinbox.setValue(16)
        self.length_spinbox.valueChanged.connect(self.update_password)
        options_layout.addRow("Length:", self.length_spinbox)

        # Character Sets
        self.uppercase_check = QCheckBox("Uppercase (A-Z)")
        self.uppercase_check.setChecked(True)
        self.uppercase_check.stateChanged.connect(self.update_password)
        options_layout.addRow(self.uppercase_check)

        self.lowercase_check = QCheckBox("Lowercase (a-z)")
        self.lowercase_check.setChecked(True)
        self.lowercase_check.stateChanged.connect(self.update_password)
        options_layout.addRow(self.lowercase_check)

        self.digits_check = QCheckBox("Digits (0-9)")
        self.digits_check.setChecked(True)
        self.digits_check.stateChanged.connect(self.update_password)
        options_layout.addRow(self.digits_check)

        self.symbols_check = QCheckBox("Symbols (!@#$...?)")
        self.symbols_check.setChecked(True)
        self.symbols_check.stateChanged.connect(self.update_password)
        options_layout.addRow(self.symbols_check)

        layout.addWidget(options_group)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def update_password(self):
        """Generate and display a new password based on options."""
        try:
            length = self.length_spinbox.value()
            use_upper = self.uppercase_check.isChecked()
            use_lower = self.lowercase_check.isChecked()
            use_digits = self.digits_check.isChecked()
            use_symbols = self.symbols_check.isChecked()

            # Ensure at least one character set is selected
            if not any([use_upper, use_lower, use_digits, use_symbols]):
                self.password_display.setText("Select at least one character set")
                self.generated_password = ""
                # Optionally re-check a default like lowercase
                # self.lowercase_check.setChecked(True)
                return

            self.generated_password = generate_password(
                length=length,
                use_uppercase=use_upper,
                use_lowercase=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols
            )
            self.password_display.setText(self.generated_password)
        except ValueError as e:
            self.password_display.setText(f"Error: {e}")
            self.generated_password = ""
        except Exception as e:
            log.error(f"Error generating password: {e}")
            self.password_display.setText("Generation Error")
            self.generated_password = ""

    def get_password(self):
        return self.generated_password


# --- Settings Dialog ---
class SettingsDialog(QDialog):
    # Signal emitted when 2FA status changes
    tfa_status_changed = pyqtSignal(bool)
    # Signal emitted when categories are updated
    categories_updated = pyqtSignal(list)

    def __init__(self, parent=None, db_manager=None, cipher_suite=None):
        super().__init__(parent)
        self.db = db_manager
        self.cipher = cipher_suite
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        self.new_categories = []  # Track newly added categories

        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        tab_widget = QTabWidget()

        # --- General Tab ---
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)

        # Auto-lock timeout
        self.autolock_spinbox = QSpinBox()
        self.autolock_spinbox.setRange(1, 120)  # 1 min to 2 hours
        self.autolock_spinbox.setSuffix(" minutes")
        general_layout.addRow("Auto-lock after inactivity:", self.autolock_spinbox)

        # Clipboard clear timeout
        self.clipboard_spinbox = QSpinBox()
        self.clipboard_spinbox.setRange(10, 120)  # 10 sec to 2 mins
        self.clipboard_spinbox.setSuffix(" seconds")
        general_layout.addRow("Clear clipboard after:", self.clipboard_spinbox)

        tab_widget.addTab(general_tab, "General")

        # --- Security Tab ---
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)

        # Master Password Change
        change_mp_button = QPushButton(qta.icon('fa5s.key'), " Change Master Password...")
        change_mp_button.clicked.connect(self.change_master_password)
        security_layout.addWidget(change_mp_button)

        security_layout.addWidget(self.create_separator())

        # Two-Factor Authentication
        tfa_group = QGroupBox("Two-Factor Authentication (TOTP)")
        tfa_layout = QVBoxLayout(tfa_group)

        self.tfa_status_label = QLabel("Status: Disabled")
        tfa_layout.addWidget(self.tfa_status_label)

        self.tfa_enable_button = QPushButton(qta.icon('fa5s.check-circle'), " Enable 2FA...")
        self.tfa_enable_button.clicked.connect(self.enable_2fa)
        tfa_layout.addWidget(self.tfa_enable_button)

        self.tfa_disable_button = QPushButton(qta.icon('fa5s.times-circle'), " Disable 2FA")
        self.tfa_disable_button.clicked.connect(self.disable_2fa)
        tfa_layout.addWidget(self.tfa_disable_button)

        security_layout.addWidget(tfa_group)
        security_layout.addStretch()
        tab_widget.addTab(security_tab, "Security")

        # --- Vault Health Tab ---
        health_tab = QWidget()
        health_layout = QVBoxLayout(health_tab)
        self.health_report_text = QTextEdit()
        self.health_report_text.setReadOnly(True)
        health_layout.addWidget(self.health_report_text)
        check_health_btn = QPushButton(qta.icon('fa5s.heartbeat'), " Check Vault Health")
        check_health_btn.clicked.connect(self.run_vault_health_check)
        health_layout.addWidget(check_health_btn)
        tab_widget.addTab(health_tab, "Vault Health")

        # --- Categories Tab ---
        categories_tab = QWidget()
        categories_layout = QVBoxLayout(categories_tab)
        categories_group = QGroupBox("Manage Categories")
        categories_group_layout = QHBoxLayout(categories_group)

        self.category_list = QListWidget()
        self.category_list.itemDoubleClicked.connect(self.rename_category)
        categories_group_layout.addWidget(self.category_list)

        cat_button_layout = QVBoxLayout()
        add_cat_btn = QPushButton(qta.icon('fa5s.plus'), "")
        add_cat_btn.setToolTip("Add New Category")
        add_cat_btn.clicked.connect(self.add_category)
        rename_cat_btn = QPushButton(qta.icon('fa5s.edit'), "")
        rename_cat_btn.setToolTip("Rename Selected Category")
        rename_cat_btn.clicked.connect(self.rename_category)
        delete_cat_btn = QPushButton(qta.icon('fa5s.trash-alt'), "")
        delete_cat_btn.setToolTip("Delete Selected Category")
        delete_cat_btn.clicked.connect(self.delete_category)
        cat_button_layout.addWidget(add_cat_btn)
        cat_button_layout.addWidget(rename_cat_btn)
        cat_button_layout.addWidget(delete_cat_btn)
        cat_button_layout.addStretch()
        categories_group_layout.addLayout(cat_button_layout)
        categories_layout.addWidget(categories_group)

        tab_widget.addTab(categories_tab, "Categories")

        layout.addWidget(tab_widget)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_settings)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def create_separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def load_settings(self):
        # Load from QSettings (or DB settings table)
        settings = QSettings()  # Uses platform default location or INI file

        # General
        autolock = settings.value("general/autoLockTimeout", AUTO_LOCK_TIMEOUT_MINUTES, type=int)
        clipboard = settings.value("general/clipboardClearTimeout", CLIPBOARD_CLEAR_TIMEOUT_SECONDS, type=int)
        self.autolock_spinbox.setValue(autolock)
        self.clipboard_spinbox.setValue(clipboard)

        # Security (2FA status)
        self.update_tfa_status()

        # Categories
        self.load_categories()

    def save_settings(self):
        # Save to QSettings (or DB settings table)
        settings = QSettings()

        # General
        settings.setValue("general/autoLockTimeout", self.autolock_spinbox.value())
        settings.setValue("general/clipboardClearTimeout", self.clipboard_spinbox.value())

        # Apply changes immediately where possible (e.g., update timer in main window)
        if self.parent():
            self.parent().apply_settings()

        # Update categories
        if self.new_categories:
            self.categories_updated.emit(self.new_categories)

        self.accept()

    def update_tfa_status(self):
        is_enabled = bool(self.db.get_setting("totp_secret_encrypted"))
        if is_enabled:
            self.tfa_status_label.setText("Status: <b style='color: green;'>Enabled (Authenticator App)</b>")
            self.tfa_enable_button.setEnabled(False)
            self.tfa_disable_button.setEnabled(True)
        else:
            self.tfa_status_label.setText("Status: <span style='color: red;'>Disabled</span>")
            self.tfa_enable_button.setEnabled(True)
            self.tfa_disable_button.setEnabled(False)
        self.tfa_status_changed.emit(is_enabled)

    def enable_2fa(self):
        if not self.cipher:
            QMessageBox.critical(self, "Error", "Cannot enable 2FA without a valid encryption key.")
            return
        # Generate TOTP secret and provisioning URI
        secret = generate_totp_secret()
        account_name = self.db.get_user_email() or "user"
        uri = get_totp_uri(secret, account_name, TOTP_ISSUER_NAME)

        # Dialog with QR code and manual code
        setup_dialog = QDialog(self)
        setup_dialog.setWindowTitle("Set up Authenticator App")
        layout = QVBoxLayout(setup_dialog)
        layout.addWidget(QLabel("Scan the QR code in your authenticator app, or enter the secret manually."))

        qr_path = generate_qr_code_image(uri, filename="totp_qr.png")
        if qr_path:
            qr_label = QLabel()
            try:
                qr_pixmap = QPixmap(qr_path)
                qr_label.setPixmap(qr_pixmap.scaled(220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            except Exception:
                qr_label.setText("QR not available")
            layout.addWidget(qr_label)

        secret_label = QLabel(f"Secret: <code>{secret}</code>")
        secret_label.setTextFormat(Qt.RichText)
        layout.addWidget(secret_label)

        code_edit = QLineEdit()
        code_edit.setPlaceholderText("Enter the 6-digit code from your app")
        layout.addWidget(code_edit)
        error_label = QLabel("")
        error_label.setStyleSheet("color: red;")
        layout.addWidget(error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(buttons)

        def verify_code():
            code = code_edit.text().strip()
            if verify_totp_code(secret, code):
                setup_dialog.accept()
            else:
                error_label.setText("Invalid code. Please try again.")
        buttons.accepted.connect(verify_code)
        buttons.rejected.connect(setup_dialog.reject)

        if setup_dialog.exec_() != QDialog.Accepted:
            QMessageBox.warning(self, "2FA Setup Cancelled", "Setup was cancelled or the code was incorrect.")
            return

        # Encrypt and store secret
        enc_secret = encrypt_data(secret.encode('utf-8'), self.cipher)
        if not enc_secret:
            QMessageBox.critical(self, "Error", "Failed to secure 2FA secret.")
            return
        if self.db.set_setting("totp_secret_encrypted", enc_secret):
            QMessageBox.information(self, "Success", "Authenticator App 2FA enabled successfully!")
            self.update_tfa_status()
        else:
            QMessageBox.critical(self, "Error", "Failed to save 2FA settings to the database.")

    def disable_2fa(self):
        reply = QMessageBox.warning(self, "Disable 2FA",
                                    "Are you sure you want to disable Two-Factor Authentication?\n"
                                    "You will no longer be prompted for a code at login.",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.db.set_setting("totp_secret_encrypted", ""):
                QMessageBox.information(self, "Success", "Two-Factor Authentication has been disabled.")
                self.update_tfa_status()
            else:
                QMessageBox.critical(self, "Error", "Failed to update 2FA settings in the database.")

    def change_master_password(self):
        # Delegate to the main window's method
        if self.parent() and hasattr(self.parent(), 'change_master_password'):
            # Close the settings dialog first? Or keep it open? Close it.
            self.accept()  # Save any other changes
            self.parent().change_master_password()

    def run_vault_health_check(self):
        """Performs checks on the vault and displays a report."""
        if not self.cipher or not self.db:
            self.health_report_text.setPlainText("Error: Cannot perform check. Database or encryption key unavailable.")
            return

        start_time = time.time()
        self.health_report_text.setPlainText("Running vault health check...")
        QApplication.processEvents()  # Update UI

        all_passwords_details = []
        all_raw_passwords = self.db.get_all_passwords()  # Gets (id, site, username, category)
        total_entries = len(all_raw_passwords)
        progress = QProgressDialog("Checking passwords...", "Cancel", 0, total_entries, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("Vault Health Check")
        progress.show()

        for i, entry_summary in enumerate(all_raw_passwords):
            if progress.wasCanceled():
                self.health_report_text.append("\nCheck canceled by user.")
                return
            progress.setValue(i)
            entry_id = entry_summary[0]
            details = self.db.get_password_details(entry_id)  # Fetch full details including encrypted password
            if details:
                # Decrypt password
                encrypted_pass = details[3]  # password column
                decrypted_bytes = decrypt_data(encrypted_pass, self.cipher)
                if decrypted_bytes:
                    plain_password = decrypted_bytes.decode('utf-8')
                    all_passwords_details.append({
                        "id": details[0],
                        "site": details[1],
                        "username": details[2],
                        "password": plain_password,
                        "updated_at": details[8]  # updated_at timestamp
                    })
                else:
                    log.warning(f"Health Check: Failed to decrypt password for entry ID {entry_id}")
                    # How to report this? Add to a separate list?
            QApplication.processEvents()

        progress.setValue(total_entries)

        weak_passwords = []
        reused_passwords = {}  # password -> list of sites/usernames
        old_passwords = []  # Passwords not updated recently

        password_map = {}
        for entry in all_passwords_details:
            password = entry["password"]
            site_user = f"{entry['site']} / {entry['username']}"

            # Check Strength
            strength = check_password_strength(password)
            if strength['score'] < 3:  # Score 0, 1, 2 (Very Weak, Weak, Fair)
                weak_passwords.append(f"- {site_user} (Strength: {strength['strength_description']})")

            # Check Reuse
            if password in password_map:
                password_map[password].append(site_user)
            else:
                password_map[password] = [site_user]

            # Check Age (e.g., older than 1 year) - Robust datetime parsing
            from datetime import datetime, timedelta
            def _parse_to_datetime(value):
                try:
                    if value is None:
                        return None
                    # If it's a datetime-like object
                    if hasattr(value, 'isoformat') and hasattr(value, 'strftime'):
                        return value
                    # If it's a string, try multiple formats
                    if isinstance(value, str):
                        s = value.strip()
                        if not s:
                            return None
                        # Normalize common ISO forms
                        s = s.replace('Z', '')
                        if 'T' in s:
                            s_base = s.split('.')[0]
                            try:
                                return datetime.fromisoformat(s_base)
                            except Exception:
                                pass
                        # Try space-separated format
                        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                            try:
                                return datetime.strptime(s.split('.')[0], fmt)
                            except Exception:
                                continue
                    # Fallback: not parseable
                    return None
                except Exception:
                    return None

            updated_time = _parse_to_datetime(entry.get('updated_at'))
            if updated_time and updated_time < datetime.now() - timedelta(days=365):
                old_passwords.append(f"- {site_user} (Last updated: {updated_time.strftime('%Y-%m-%d')})")

        # Filter reused passwords
        for password, users in password_map.items():
            if len(users) > 1:
                reused_passwords[password] = users

        # --- Generate Report ---
        report = f"Vault Health Check Report ({time.strftime('%Y-%m-%d %H:%M:%S')})\n"
        report += f"Checked {len(all_passwords_details)} entries in {time.time() - start_time:.2f} seconds.\n"
        report += "=" * 30 + "\n\n"

        if weak_passwords:
            report += f"Weak Passwords ({len(weak_passwords)} Found):\n"
            report += "\n".join(weak_passwords) + "\n\n"
        else:
            report += "✅ No weak passwords found.\n\n"

        if reused_passwords:
            report += f"Reused Passwords ({len(reused_passwords)} Instances Found):\n"
            for pwd, users in reused_passwords.items():
                report += f"- Password reused for: {', '.join(users)}\n"
            report += "\n"
        else:
            report += "✅ No reused passwords found.\n\n"

        if old_passwords:
            report += f"Potentially Old Passwords ({len(old_passwords)} Found - Older than 1 year):\n"
            report += "\n".join(old_passwords) + "\n\n"
        else:
            report += "✅ No passwords older than 1 year found.\n\n"

        self.health_report_text.setPlainText(report)

    # --- Category Management ---
    def load_categories(self):
        self.category_list.clear()
        categories = self.db.get_all_categories()
        self.category_list.addItems(categories)

    def add_category(self):
        text, ok = QInputDialog.getText(self, "Add Category", "Enter new category name:")
        if ok and text.strip():
            new_category = text.strip()
            # Check if exists (case-insensitive check might be good)
            items = self.category_list.findItems(new_category, Qt.MatchFixedString)
            if not items:
                self.category_list.addItem(new_category)
                # Add to new categories list so it can be used in the app immediately
                self.new_categories.append(new_category)
            else:
                QMessageBox.warning(self, "Duplicate", f"Category '{new_category}' already exists.")

    def rename_category(self):
        selected_item = self.category_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Rename Category", "Please select a category to rename.")
            return

        old_category = selected_item.text()
        if old_category == 'Uncategorized':
            QMessageBox.warning(self, "Rename Category", "Cannot rename the default 'Uncategorized' category.")
            return

        text, ok = QInputDialog.getText(self, "Rename Category", f"Enter new name for '{old_category}':",
                                        QLineEdit.Normal, old_category)

        if ok and text.strip():
            new_category = text.strip()
            if new_category == old_category:
                return  # No change

            # Check if new name already exists
            items = self.category_list.findItems(new_category, Qt.MatchFixedString)
            if items and items[0] != selected_item:
                QMessageBox.warning(self, "Duplicate", f"Category '{new_category}' already exists.")
                return

            # Confirmation
            reply = QMessageBox.question(self, "Confirm Rename",
                                         f"This will update all entries currently using the category '{old_category}' to '{new_category}'. Proceed?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                # Update in Database (requires a specific DB method)
                # success = self.db.rename_category(old_category, new_category) # Needs implementation in DatabaseManager
                # For now, we simulate by just changing the list item. Actual DB update is missing.
                # A proper implementation requires iterating through passwords table.
                log.warning(
                    f"Database category rename function not implemented. Renaming '{old_category}' to '{new_category}' in UI only.")
                selected_item.setText(new_category)
                QMessageBox.information(self, "Rename Category",
                                        f"Category '{old_category}' renamed to '{new_category}' (UI only).")

    def delete_category(self):
        selected_item = self.category_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Delete Category", "Please select a category to delete.")
            return

        category_to_delete = selected_item.text()
        if category_to_delete == 'Uncategorized':
            QMessageBox.warning(self, "Delete Category", "Cannot delete the default 'Uncategorized' category.")
            return

        # Confirmation
        reply = QMessageBox.question(self, "Confirm Delete",
                                     f"Are you sure you want to delete the category '{category_to_delete}'?\n"
                                     f"Entries using this category will be set to 'Uncategorized'.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # Update in Database (requires a specific DB method)
            # success = self.db.delete_category(category_to_delete) # Needs implementation
            # This method should update entries using this category to 'Uncategorized'
            log.warning(
                f"Database category delete function not implemented. Deleting '{category_to_delete}' from UI only.")
            self.category_list.takeItem(self.category_list.row(selected_item))
            QMessageBox.information(self, "Delete Category",
                                    f"Category '{category_to_delete}' deleted (UI only). Entries need manual update or DB function.")


# --- Main Application Window ---
class PasswordManagerGUI(QMainWindow):
    lock_status_changed = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        # Add category colors dictionary
        self.category_colors = {
            'Uncategorized': '#808080',  # Gray
            'Social': '#FF6B6B',         # Red
            'Email': '#4ECDC4',          # Teal
            'Work': '#45B7D1',           # Blue
            'Shopping': '#96CEB4',       # Green
            'Finance': '#FFEEAD',        # Yellow
            'Entertainment': '#D4A5A5',  # Pink
            'Education': '#9B59B6',      # Purple
            'Health': '#E67E22',         # Orange
            'Travel': '#3498DB',         # Light Blue
        }
        # Add a method to get a color for a category
        self.get_category_color = lambda cat: self.category_colors.get(cat, self._generate_color_for_category(cat))
        
        self.db = DatabaseManager(DB_PATH)
        self.cipher: Optional[Fernet] = None
        self.current_salt: Optional[bytes] = None
        self.current_master_hash: Optional[str] = None
        self.is_locked = True  # Start locked
        self.last_activity_time = time.time()
        self.inactivity_timer = QTimer(self)
        self.clipboard_clear_timeout = CLIPBOARD_CLEAR_TIMEOUT_SECONDS
        self.auto_lock_timeout = AUTO_LOCK_TIMEOUT_MINUTES * 60 * 1000

        is_potentially_first_run = not self.db.get_master_password_hash()

        if not self.run_initial_setup_or_login():
            log.critical("Initial setup/login failed. Exiting.")
            app_instance = QApplication.instance()
            if app_instance:
                QTimer.singleShot(0, app_instance.quit)
            else:
                sys.exit(1)
            return

        self.init_ui()  # Initialize all UI elements

        if is_potentially_first_run and not self.is_locked:
            QMessageBox.information(self, "Setup Successful",
                                    "Master password has been set successfully!\n"
                                    "Your vault is now ready to use.")

        self.apply_settings()
        self.setup_inactivity_timer()
        self.load_categories_into_sidebar()
        self.load_passwords()
        self.update_lock_status_ui()

    def run_initial_setup_or_login(self) -> bool:
        master_data = self.db.get_master_password_hash()
        if not master_data:
            log.info("No master password found. Starting first time setup.")
            return self.first_time_setup()
        else:
            log.info("Master password found. Proceeding to login.")
            self.current_master_hash, self.current_salt = master_data
            return self.login()

    def first_time_setup(self) -> bool:
        QMessageBox.information(self, "Welcome",
                                "Welcome to Secure Password Manager!\n"
                                "Please create a strong master password for your new vault.")

        dialog = PasswordDialog(self, "Create your master password:", is_confirmation=True, title="First Time Setup")
        if dialog.exec_() != QDialog.Accepted:
            log.warning("First time setup cancelled by user.")
            return False

        password = dialog.get_password()
        if not password:
            QMessageBox.critical(self, "Error", "Master password cannot be empty!")
            return False

        password_hash, salt = hash_password(password)
        if not self.db.set_master_password(password_hash, salt):
            QMessageBox.critical(self, "Database Error", "Failed to save the master password!")
            return False

        try:
            key = generate_encryption_key_from_password(password, salt)
            self.cipher = Fernet(key)
            self.current_salt = salt
            self.current_master_hash = password_hash
            self.is_locked = False
            log.info("Master password set successfully internally. Vault unlocked.")
            return True
        except Exception as e:
            log.error(f"Failed to derive encryption key during setup: {e}", exc_info=True)
            QMessageBox.critical(self, "Encryption Error", f"Failed to prepare encryption key: {e}")
            return False

    def login(self, prompt_message="Enter master password:") -> bool:
        if not self.current_master_hash or not self.current_salt:
            master_data = self.db.get_master_password_hash()
            if not master_data:
                log.error("Login attempt failed: Master password hash not found.")
                QMessageBox.critical(self, "Error", "Master password data not found. Cannot log in.")
                return False
            self.current_master_hash, self.current_salt = master_data

        # TOTP-based 2FA detection
        enc_totp_secret = self.db.get_setting("totp_secret_encrypted")
        is_2fa_enabled = bool(enc_totp_secret)

        for attempt in range(3):
            dialog = PasswordDialog(self, prompt_message, title="Unlock Vault")
            if dialog.exec_() != QDialog.Accepted:
                log.warning("Login cancelled by user.")
                return False

            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Login Failed", "Password cannot be empty.")
                continue

            if verify_password(password, self.current_master_hash, self.current_salt):
                try:
                    key = generate_encryption_key_from_password(password, self.current_salt)
                    self.cipher = Fernet(key)

                    if is_2fa_enabled:
                        # Verify TOTP code from authenticator app
                        secret_bytes = decrypt_data(enc_totp_secret, self.cipher)
                        if not secret_bytes:
                            QMessageBox.critical(self, "2FA Error", "Failed to read TOTP secret. Cannot proceed.")
                            self.cipher = None
                            return False
                        secret = secret_bytes.decode('utf-8')
                        for otp_attempt in range(3):
                            code, ok2 = QInputDialog.getText(self, "Two-Factor Authentication", "Enter the 6-digit code from your authenticator app:")
                            if not ok2:
                                log.warning("2FA cancelled by user.")
                                self.cipher = None
                                return False
                            if verify_totp_code(secret, code.strip()):
                                self.is_locked = False
                                self.last_activity_time = time.time()
                                log.info("Login successful. Vault unlocked internally.")
                                return True
                            else:
                                remaining = 2 - otp_attempt
                                if remaining >= 0:
                                    QMessageBox.warning(self, "Login Failed", f"Incorrect code. {remaining} attempts remaining.")
                                if otp_attempt == 2:
                                    log.warning("Too many failed TOTP attempts.")
                                    QMessageBox.critical(self, "Login Failed", "Too many failed 2FA attempts.")
                                    self.cipher = None
                                    return False
                        return False
                    else:
                        self.is_locked = False
                        self.last_activity_time = time.time()
                        log.info("Login successful. Vault unlocked internally.")
                        return True
                except Exception as e:
                    log.error(f"Failed to derive encryption key during login: {e}", exc_info=True)
                    QMessageBox.critical(self, "Encryption Error", f"Failed to prepare encryption key: {e}")
                    self.cipher = None
                    return False
            remaining = 2 - attempt
            if remaining > 0:
                QMessageBox.warning(self, "Login Failed", f"Incorrect master password. {remaining} attempts remaining.")
            else:
                log.warning("Too many failed login attempts.")
                QMessageBox.critical(self, "Login Failed", "Too many failed login attempts. Exiting application.")
                app_instance = QApplication.instance()
                if app_instance:
                    QTimer.singleShot(0, app_instance.quit)
                else:
                    sys.exit(1)
                return False
        return False

    def _create_separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def init_ui(self):
        self.setWindowTitle(f"{APP_NAME} - v{APP_VERSION}")
        self.setGeometry(100, 100, 1100, 700)
        try:
            self.setWindowIcon(qta.icon('fa5s.shield-alt'))
        except Exception:
            pass

        self.central_widget_stack = QStackedWidget()
        self.setCentralWidget(self.central_widget_stack)

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: gray; }")
        splitter.setHandleWidth(2)

        left_widget = QWidget()
        left_widget.setStyleSheet("background-color: #2c3e50;")
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(5, 10, 5, 10)
        left_layout.setSpacing(5)

        search_frame = QFrame()
        search_frame.setStyleSheet("background-color: #34495e; border-radius: 15px;")
        search_layout = QHBoxLayout(search_frame)
        search_layout.setContentsMargins(10, 5, 10, 5)
        search_icon = QLabel()
        try:
            search_icon.setPixmap(qta.icon('fa5s.search', color='lightgray').pixmap(QSize(16, 16)))
        except Exception:
            search_icon.setText("🔍")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search Vault")
        self.search_edit.setStyleSheet("border: none; background: transparent; color: white;")
        self.search_edit.textChanged.connect(self.filter_passwords)
        search_layout.addWidget(search_icon)
        search_layout.addWidget(self.search_edit)
        left_layout.addWidget(search_frame)
        left_layout.addSpacing(10)

        self.filter_list = QListWidget()
        self.filter_list.setStyleSheet("""
            QListWidget { border: none; background-color: transparent; color: white; outline: 0; }
            QListWidget::item { padding: 8px 10px; border-radius: 5px; }
            QListWidget::item:hover { background-color: #34495e; }
            QListWidget::item:selected { background-color: #4a69bd; color: white; font-weight: bold; }
        """)
        self.filter_list.setIconSize(QSize(18, 18))
        self.filter_list.setFixedWidth(180)

        all_items = QListWidgetItem("All Items")
        try:
            all_items.setIcon(qta.icon('fa5s.archive', color='lightgray'))
        except Exception:
            pass
        all_items.setData(Qt.UserRole, "filter_all")
        self.filter_list.addItem(all_items)
        self.filter_list.addItem(QListWidgetItem(" "))
        self.folders_header = QListWidgetItem("CATEGORIES");
        self.folders_header.setFlags(Qt.NoItemFlags);
        self.folders_header.setForeground(QColor('gray'));
        self.filter_list.addItem(self.folders_header)
        self.uncategorized_item = QListWidgetItem("Uncategorized")
        try:
            self.uncategorized_item.setIcon(qta.icon('fa5s.folder', color='lightgray'))
        except Exception:
            pass
        self.uncategorized_item.setData(Qt.UserRole, "category_Uncategorized")
        self.filter_list.addItem(self.uncategorized_item)
        self.filter_list.currentItemChanged.connect(self.on_filter_selected)
        left_layout.addWidget(self.filter_list)
        left_layout.addStretch()
        settings_btn = QPushButton(" Settings")
        try:
            settings_btn.setIcon(qta.icon('fa5s.cog', color='lightgray'))
        except Exception:
            pass
        settings_btn.setStyleSheet(
            "QPushButton { color: lightgray; text-align: left; padding: 10px; border: none; background-color: transparent; } QPushButton:hover { background-color: #34495e; }")
        settings_btn.clicked.connect(self.open_settings)
        left_layout.addWidget(settings_btn)

        middle_widget = QWidget()
        middle_layout = QVBoxLayout(middle_widget)
        middle_layout.setContentsMargins(0, 5, 0, 0)
        middle_layout.setSpacing(0)
        list_header_layout = QHBoxLayout();
        list_header_layout.setContentsMargins(10, 0, 10, 5)
        self.item_count_label = QLabel("Items: 0");
        self.item_count_label.setStyleSheet("color: gray;")
        list_header_layout.addWidget(self.item_count_label);
        list_header_layout.addStretch();
        middle_layout.addLayout(list_header_layout)
        self.password_list = QListWidget()
        self.password_list.setStyleSheet(
            "QListWidget { border: none; } QListWidget::item { border-bottom: 1px solid #3a3a3a; }")
        self.password_list.currentItemChanged.connect(self.on_password_selected)
        self.password_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.password_list.customContextMenuRequested.connect(self.show_list_context_menu)
        # Enable multiple selection
        self.password_list.setSelectionMode(QListWidget.ExtendedSelection)
        middle_layout.addWidget(self.password_list)

        right_widget = QFrame();
        right_widget.setFrameShape(QFrame.StyledPanel);
        right_widget.setStyleSheet("background-color: #f0f0f0;")
        self.right_layout = QVBoxLayout(right_widget);
        self.right_layout.setContentsMargins(15, 15, 15, 15);
        self.right_layout.setSpacing(10)
        self.detail_stack = QStackedWidget()
        placeholder_widget = QWidget();
        placeholder_layout = QVBoxLayout(placeholder_widget);
        placeholder_layout.addStretch()
        placeholder_icon = QLabel();
        try:
            placeholder_icon.setPixmap(qta.icon('fa5s.shield-alt', color='#bdc3c7').pixmap(QSize(64, 64)))
        except Exception:
            placeholder_icon.setText("🛡️")
        placeholder_icon.setAlignment(Qt.AlignCenter);
        placeholder_layout.addWidget(placeholder_icon)
        placeholder_label = QLabel("Select an item to view details");
        placeholder_label.setAlignment(Qt.AlignCenter);
        placeholder_label.setStyleSheet("color: gray; font-size: 14px;");
        placeholder_layout.addWidget(placeholder_label)
        placeholder_layout.addStretch();
        self.detail_stack.addWidget(placeholder_widget)

        self.detail_scroll_area = QScrollArea();
        self.detail_scroll_area.setWidgetResizable(True);
        self.detail_scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.detail_widget = QWidget();
        self.detail_widget.setStyleSheet("background-color: white; border-radius: 8px;");
        self.detail_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.detail_layout = QVBoxLayout(self.detail_widget);
        self.detail_layout.setContentsMargins(20, 20, 20, 20);
        self.detail_layout.setSpacing(15)
        header_layout = QHBoxLayout();
        self.detail_icon = QLabel();
        self.detail_icon.setFixedSize(48, 48);
        header_layout.addWidget(self.detail_icon)
        self.detail_site_name = QLabel("Site Name");
        self.detail_site_name.setStyleSheet("font-size: 20px; font-weight: bold;");
        header_layout.addWidget(self.detail_site_name)
        header_layout.addStretch();
        self.detail_layout.addLayout(header_layout)
        self.detail_layout.addWidget(self._create_separator())

        detail_form_layout = QFormLayout();
        detail_form_layout.setRowWrapPolicy(QFormLayout.WrapLongRows);
        detail_form_layout.setLabelAlignment(Qt.AlignRight);
        detail_form_layout.setHorizontalSpacing(20);
        detail_form_layout.setVerticalSpacing(10)
        self.username_value = QLineEdit();
        self.username_value.setReadOnly(True);
        self.username_value.setStyleSheet("border: none; background: transparent;");
        username_layout = self.create_field_layout(self.username_value, self.copy_username);
        detail_form_layout.addRow("Username:", username_layout)
        self.password_value = QLineEdit();
        self.password_value.setReadOnly(True);
        self.password_value.setEchoMode(QLineEdit.Password);
        self.password_value.setStyleSheet("border: none; background: transparent;");
        password_layout = self.create_field_layout(self.password_value, self.copy_password, show_toggle=True);
        detail_form_layout.addRow("Password:", password_layout)
        self.detail_strength_label = QLabel("Strength: N/A");
        self.detail_strength_label.setStyleSheet("font-size: 10px; color: gray;");
        detail_form_layout.addRow("", self.detail_strength_label)
        self.website_value = QLineEdit();
        self.website_value.setReadOnly(True);
        self.website_value.setStyleSheet("border: none; background: transparent;");
        website_layout = self.create_field_layout(self.website_value, self.copy_website, show_open=True);
        detail_form_layout.addRow("Website:", website_layout)
        self.category_value = QLabel("-");
        detail_form_layout.addRow("Category:", self.category_value)
        self.notes_display = QTextEdit();
        self.notes_display.setReadOnly(True);
        self.notes_display.setStyleSheet("border: 1px solid #e0e0e0; background-color: #f8f8f8; border-radius: 4px;");
        self.notes_display.setMaximumHeight(80);
        self.notes_display.setVisible(False);
        detail_form_layout.addRow("Notes:", self.notes_display)
        self.created_value = QLabel("-");
        self.created_value.setStyleSheet("color: gray; font-size: 10px;");
        detail_form_layout.addRow("Created:", self.created_value)
        self.updated_value = QLabel("-");
        self.updated_value.setStyleSheet("color: gray; font-size: 10px;");
        detail_form_layout.addRow("Updated:", self.updated_value)
        self.detail_layout.addLayout(detail_form_layout);
        self.detail_layout.addStretch()
        self.detail_layout.addWidget(self._create_separator())
        edit_tools_layout = QHBoxLayout();
        edit_tools_layout.addStretch()
        edit_btn = QPushButton(" Edit");
        try:
            edit_btn.setIcon(qta.icon('fa5s.pencil-alt'))
        except Exception:
            pass
        edit_btn.clicked.connect(self.edit_password);
        edit_tools_layout.addWidget(edit_btn)
        delete_btn = QPushButton(" Delete");
        delete_btn.setStyleSheet("color: red;")
        try:
            delete_btn.setIcon(qta.icon('fa5s.trash-alt'))
        except Exception:
            pass
        delete_btn.clicked.connect(self.delete_password);
        edit_tools_layout.addWidget(delete_btn)
        self.detail_layout.addLayout(edit_tools_layout)
        self.detail_scroll_area.setWidget(self.detail_widget);
        self.detail_stack.addWidget(self.detail_scroll_area)
        self.right_layout.addWidget(self.detail_stack)

        splitter.addWidget(left_widget);
        splitter.addWidget(middle_widget);
        splitter.addWidget(right_widget)
        splitter.setSizes([200, 350, 550]);
        splitter.setCollapsible(0, False);
        splitter.setCollapsible(2, False)
        main_layout.addWidget(splitter);
        self.central_widget_stack.addWidget(main_widget)

        locked_widget = QWidget();
        locked_layout = QVBoxLayout(locked_widget);
        locked_widget.setStyleSheet("background-color: rgba(44, 62, 80, 0.9);")
        locked_layout.addStretch();
        lock_icon = QLabel()
        try:
            lock_icon.setPixmap(qta.icon('fa5s.lock', color='white').pixmap(QSize(80, 80)))
        except Exception:
            lock_icon.setText("🔒")
        lock_icon.setAlignment(Qt.AlignCenter);
        locked_layout.addWidget(lock_icon)
        locked_label = QLabel("Vault is Locked");
        locked_label.setAlignment(Qt.AlignCenter);
        locked_label.setStyleSheet("color: white; font-size: 24px; font-weight: bold;");
        locked_layout.addWidget(locked_label)
        locked_layout.addSpacing(20)
        unlock_button = QPushButton(" Unlock Vault")
        try:
            unlock_button.setIcon(qta.icon('fa5s.key', color='white'))
        except Exception:
            pass
        unlock_button.setStyleSheet(
            "QPushButton { color: white; font-size: 16px; padding: 10px 20px; background-color: #3498db; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        unlock_button.clicked.connect(self.unlock_vault);
        unlock_button.setMinimumWidth(150);
        locked_layout.addWidget(unlock_button, alignment=Qt.AlignCenter)
        locked_layout.addStretch();
        self.central_widget_stack.addWidget(locked_widget)
        self.central_widget_stack.setCurrentIndex(1 if self.is_locked else 0)

        self.setup_actions();
        self.setup_menu();
        self.setup_toolbar();
        self.setup_status_bar()
        self.update_lock_status_ui()
        QApplication.instance().installEventFilter(self)

    def create_field_layout(self, line_edit, copy_func, show_toggle=False, show_open=False):
        layout = QHBoxLayout();
        layout.setContentsMargins(0, 0, 0, 0);
        layout.setSpacing(5);
        layout.addWidget(line_edit)
        if show_toggle:
            toggle_btn = QPushButton();
            toggle_btn.setToolTip("Show/Hide Password");
            toggle_btn.setCheckable(True);
            toggle_btn.setFixedSize(28, 28);
            toggle_btn.setIconSize(QSize(14, 14))
            try:
                toggle_btn.setIcon(qta.icon('fa5s.eye'))
            except Exception:
                toggle_btn.setText("👁️")
            toggle_btn.toggled.connect(self.toggle_password_visibility_detail);
            layout.addWidget(toggle_btn)
        if show_open:
            open_btn = QPushButton();
            open_btn.setToolTip("Open Website");
            open_btn.setFixedSize(28, 28);
            open_btn.setIconSize(QSize(14, 14))
            try:
                open_btn.setIcon(qta.icon('fa5s.external-link-alt'))
            except Exception:
                open_btn.setText("🌐")
            open_btn.clicked.connect(self.open_website);
            layout.addWidget(open_btn)
        copy_btn = QPushButton();
        copy_btn.setToolTip("Copy to Clipboard");
        copy_btn.setFixedSize(28, 28);
        copy_btn.setIconSize(QSize(14, 14))
        try:
            copy_btn.setIcon(qta.icon('fa5s.copy'))
        except Exception:
            copy_btn.setText("📋")
        copy_btn.clicked.connect(copy_func);
        layout.addWidget(copy_btn)
        return layout

    def setup_actions(self):
        self.add_action = QAction('&Add New Entry', self);
        self.add_action.setShortcut('Ctrl+N');
        self.add_action.triggered.connect(self.add_password)
        self.import_action = QAction('&Import Vault...', self);
        self.import_action.triggered.connect(self.import_vault_triggered)
        self.export_action = QAction('&Export Vault...', self);
        self.export_action.triggered.connect(self.export_vault_triggered)
        self.lock_action = QAction('&Lock Vault', self);
        self.lock_action.setShortcut('Ctrl+L');
        self.lock_action.triggered.connect(self.lock_vault)
        self.unlock_action = QAction('&Unlock Vault', self);
        self.unlock_action.triggered.connect(self.unlock_vault)
        self.exit_action = QAction('E&xit', self);
        self.exit_action.setShortcut('Ctrl+Q');
        self.exit_action.triggered.connect(self.close)
        self.edit_action = QAction('&Edit Entry', self);
        self.edit_action.triggered.connect(self.edit_password);
        self.edit_action.setEnabled(False)
        self.delete_action = QAction('&Delete Entry', self);
        self.delete_action.triggered.connect(self.delete_password);
        self.delete_action.setEnabled(False)
        self.copy_user_action = QAction('Copy &Username', self);
        self.copy_user_action.triggered.connect(self.copy_username);
        self.copy_user_action.setEnabled(False)
        self.copy_pass_action = QAction('Copy &Password', self);
        self.copy_pass_action.triggered.connect(self.copy_password);
        self.copy_pass_action.setEnabled(False)
        self.settings_action = QAction('&Settings...', self);
        self.settings_action.triggered.connect(self.open_settings)
        self.change_master_action = QAction('Change &Master Password...', self);
        self.change_master_action.triggered.connect(self.change_master_password)
        self.about_action = QAction('&About', self);
        self.about_action.triggered.connect(self.show_about)
        # Add icons to actions if qta is available
        try:
            self.add_action.setIcon(qta.icon('fa5s.plus-circle'))
            self.import_action.setIcon(qta.icon('fa5s.file-import'))
            self.export_action.setIcon(qta.icon('fa5s.file-export'))
            self.lock_action.setIcon(qta.icon('fa5s.lock'))
            self.unlock_action.setIcon(qta.icon('fa5s.unlock'))
            self.exit_action.setIcon(qta.icon('fa5s.sign-out-alt'))
            self.edit_action.setIcon(qta.icon('fa5s.edit'))
            self.delete_action.setIcon(qta.icon('fa5s.trash-alt'))
            self.copy_user_action.setIcon(qta.icon('fa5s.user'))
            self.copy_pass_action.setIcon(qta.icon('fa5s.key'))
            self.settings_action.setIcon(qta.icon('fa5s.cog'))
            self.about_action.setIcon(qta.icon('fa5s.info-circle'))
        except Exception as e:
            log.warning(f"Could not set all qta icons for actions: {e}")

    def setup_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File');
        file_menu.addAction(self.add_action);
        file_menu.addSeparator();
        file_menu.addAction(self.import_action);
        file_menu.addAction(self.export_action);
        file_menu.addSeparator();
        file_menu.addAction(self.lock_action);
        file_menu.addAction(self.unlock_action);
        file_menu.addSeparator();
        file_menu.addAction(self.exit_action)
        edit_menu = menubar.addMenu('&Edit');
        edit_menu.addAction(self.edit_action);
        edit_menu.addAction(self.delete_action);
        edit_menu.addSeparator();
        edit_menu.addAction(self.copy_user_action);
        edit_menu.addAction(self.copy_pass_action);
        edit_menu.addSeparator();
        edit_menu.addAction(self.settings_action);
        edit_menu.addAction(self.change_master_action)
        help_menu = menubar.addMenu('&Help');
        help_menu.addAction(self.about_action)

    def setup_toolbar(self):
        toolbar = self.addToolBar('Main Toolbar');
        toolbar.setIconSize(QSize(22, 22));
        toolbar.setMovable(False)
        toolbar.addAction(self.add_action);
        toolbar.addAction(self.edit_action);
        toolbar.addAction(self.delete_action);
        toolbar.addSeparator()
        toolbar.addAction(self.copy_user_action);
        toolbar.addAction(self.copy_pass_action);
        toolbar.addSeparator()
        self.lock_toolbar_button = QPushButton(" Lock");
        self.lock_toolbar_button.setCheckable(True)
        try:
            self.lock_toolbar_button.setIcon(qta.icon('fa5s.lock'))
        except Exception:
            pass
        self.lock_toolbar_button.toggled.connect(self.toggle_lock_state)
        self.lock_status_changed.connect(self.lock_toolbar_button.setChecked)
        toolbar.addWidget(self.lock_toolbar_button)
        toolbar.addSeparator();
        toolbar.addAction(self.settings_action)

    def toggle_lock_state(self, locked):
        if locked and not self.is_locked:
            self.lock_vault()
        elif not locked and self.is_locked:
            self.unlock_vault()

    def setup_status_bar(self):
        self.status_bar = self.statusBar();
        self.status_bar.showMessage("Ready", 3000)

    def setup_inactivity_timer(self):
        self.inactivity_timer.setInterval(self.auto_lock_timeout)
        self.inactivity_timer.timeout.connect(self.check_inactivity)

    def eventFilter(self, obj, event):
        activity_events = [QEvent.KeyPress, QEvent.KeyRelease, QEvent.MouseButtonPress, QEvent.MouseButtonRelease,
                           QEvent.MouseButtonDblClick, QEvent.MouseMove, QEvent.Wheel]
        if event.type() in activity_events and not self.is_locked:
            self.last_activity_time = time.time()
            self.inactivity_timer.start(self.auto_lock_timeout)
        return super().eventFilter(obj, event)

    def check_inactivity(self):
        if self.is_locked: return self.inactivity_timer.stop()
        idle_time = time.time() - self.last_activity_time
        if idle_time >= (self.auto_lock_timeout / 1000):
            log.info(f"Inactivity detected ({idle_time:.0f}s). Locking vault.")
            self.lock_vault();
            self.inactivity_timer.stop()
        else:
            remaining_time = (self.auto_lock_timeout / 1000) - idle_time
            if remaining_time > 0: self.inactivity_timer.start(int(remaining_time * 1000))

    def apply_settings(self):
        settings = QSettings()
        self.auto_lock_timeout = settings.value("general/autoLockTimeout", AUTO_LOCK_TIMEOUT_MINUTES,
                                                type=int) * 60 * 1000
        self.clipboard_clear_timeout = settings.value("general/clipboardClearTimeout", CLIPBOARD_CLEAR_TIMEOUT_SECONDS,
                                                      type=int)
        log.info(
            f"Settings applied: Auto-lock={self.auto_lock_timeout / 60000}m, Clipboard Clear={self.clipboard_clear_timeout}s")
        if self.inactivity_timer.isActive(): self.inactivity_timer.start(self.auto_lock_timeout)

    def _generate_color_for_category(self, category: str) -> str:
        """Generate a consistent color for a category based on its name."""
        # Use the category name to generate a hash
        hash_value = sum(ord(c) for c in category)
        # Generate a pastel color using the hash
        hue = (hash_value * 137) % 360  # Golden ratio to spread colors
        return f"hsl({hue}, 70%, 80%)"  # Light, pastel colors

    def load_categories_into_sidebar(self):
        """Load categories into the sidebar with colors."""
        # Clear existing categories
        for i in range(self.filter_list.count() - 1, 2, -1):  # Keep "All Items" and "Uncategorized"
            self.filter_list.takeItem(i)

        # Get categories from database
        categories = self.db.get_all_categories()
        custom_categories = self.load_custom_categories()
        all_categories = sorted(list(set(categories + custom_categories)))

        # Add each category with its color
        for category in all_categories:
            if category != 'Uncategorized':  # Skip uncategorized as it's already added
                item = QListWidgetItem(category)
                try:
                    item.setIcon(qta.icon('fa5s.folder', color=self.get_category_color(category)))
                except Exception:
                    pass
                item.setData(Qt.UserRole, f"category_{category}")
                self.filter_list.addItem(item)

    def load_custom_categories(self):
        """Load custom categories from QSettings"""
        if self.is_locked:
            return []

        settings = QSettings()
        custom_categories = settings.value("categories/custom_categories", [], type=list)
        log.info(f"Loaded {len(custom_categories)} custom categories from settings")
        return custom_categories

    def load_passwords(self, filter_data=None):
        if self.is_locked:
            self.password_list.clear()
            self.item_count_label.setText("Items: 0")
            return
        
        self.password_list.clear()
        self.clear_details()
        passwords = []
        
        # Get the right passwords based on filter
        if filter_data:
            filter_type, filter_value = filter_data.split('_', 1)
            if filter_type == "category": 
                passwords = self.db.get_passwords_by_category(filter_value)
            elif filter_type == "search": 
                passwords = self.db.search_passwords(filter_value)
            else: 
                passwords = self.db.get_all_passwords()
        else:
            current_filter = self.filter_list.currentItem()
            if current_filter:
                filter_role = current_filter.data(Qt.UserRole)
                if filter_role == "filter_all": 
                    passwords = self.db.get_all_passwords()
                elif filter_role and filter_role.startswith("category_"): 
                    cat_name = filter_role.split('_', 1)[1]
                    passwords = self.db.get_passwords_by_category(cat_name)
                else: 
                    passwords = self.db.get_all_passwords()
            else: 
                passwords = self.db.get_all_passwords()

        # Add each password to the list with category color
        for entry_id, site, username, category in passwords:
            list_item = QListWidgetItem(self.password_list)
            item_widget = PasswordListItemWidget(entry_id, site, username, category)
            # Set the category color
            item_widget.set_category_color(self.get_category_color(category))
            list_item.setSizeHint(item_widget.sizeHint())
            list_item.setData(Qt.UserRole, entry_id)
            self.password_list.addItem(list_item)
            self.password_list.setItemWidget(list_item, item_widget)
        
        self.item_count_label.setText(f"Items: {len(passwords)}")
        log.info(f"Loaded {len(passwords)} password entries.")

    def filter_passwords(self):
        if self.is_locked: return
        filter_text = self.search_edit.text().strip()

        # Debug print
        print(f"Filtering with text: {filter_text}")

        if filter_text:
            self.filter_list.setCurrentItem(None)
            self.load_passwords(filter_data=f"search_{filter_text}")
        else:
            current_filter_item = self.filter_list.currentItem()
            if current_filter_item:
                self.load_passwords(filter_data=current_filter_item.data(Qt.UserRole))
            else:
                # Fallback to all items if nothing selected
                all_items = self.filter_list.findItems("All Items", Qt.MatchExactly)
                if all_items:
                    self.filter_list.setCurrentItem(all_items[0])
                else:
                    self.load_passwords(filter_data="filter_all")

        # Debug print
        print(f"Filter complete. Current item count: {self.password_list.count()}")

    def on_filter_selected(self, current, previous):
        if self.is_locked or not current: return
        self.search_edit.clear()
        if current.data(Qt.UserRole): self.load_passwords(filter_data=current.data(Qt.UserRole))

    def on_password_selected(self, current, previous):
        if self.is_locked:
            self.clear_details()
            return

        has_selection = current is not None

        # Enable/disable actions based on selection
        self.edit_action.setEnabled(has_selection)
        self.delete_action.setEnabled(has_selection)
        self.copy_user_action.setEnabled(has_selection)
        self.copy_pass_action.setEnabled(has_selection)

        if not current:
            self.clear_details()
            self.detail_stack.setCurrentIndex(0)
            return

        entry_id = current.data(Qt.UserRole)
        if not entry_id:
            print(f"Warning: Selected item has no entry ID")  # Debug print
            log.error("Selected item has no entry ID.")
            self.clear_details()
            self.detail_stack.setCurrentIndex(0)
            return
        details = self.db.get_password_details(entry_id)
        if not details: log.error(f"Could not fetch details for entry ID {entry_id}"); QMessageBox.warning(self,
                                                                                                           "Error",
                                                                                                           "Could not load details."); self.clear_details(); self.detail_stack.setCurrentIndex(
            0); return
        _id, site, username, encrypted_password, website, category, notes, created_at, updated_at = details
        self.detail_stack.setCurrentIndex(1)
        try:
            self.detail_icon.setPixmap(qta.icon('fa5s.globe-americas', color='#34495e').pixmap(QSize(48, 48)))
        except Exception:
            pass
        self.detail_site_name.setText(site);
        self.username_value.setText(username);
        self.website_value.setText(website or "-");
        self.category_value.setText(category or "Uncategorized")
        decrypted_password = "Error Decrypting"
        if self.cipher:
            dec_bytes = decrypt_data(encrypted_password, self.cipher)
            if dec_bytes: decrypted_password = dec_bytes.decode('utf-8')
        else:
            decrypted_password = "Vault Locked"
        self.password_value.setText(decrypted_password);
        self.password_value.setEchoMode(QLineEdit.Password)
        pwd_layout = self.password_value.parent().layout()
        if pwd_layout:
            for i in range(pwd_layout.count()):
                widget = pwd_layout.itemAt(i).widget()
                if isinstance(widget, QPushButton) and widget.isCheckable(): widget.setChecked(False)
        strength = check_password_strength(decrypted_password);
        self.detail_strength_label.setText(f"Strength: {strength.get('strength_description', 'N/A')}")
        feedback = strength.get('feedback', {});
        warning = feedback.get('warning');
        suggestions = feedback.get('suggestions', [])
        tooltip_text = strength.get('strength_description', 'N/A')
        if warning: tooltip_text += f"\nWarning: {warning}"
        if suggestions: tooltip_text += "\nSuggestions:\n- " + "\n- ".join(suggestions)
        self.detail_strength_label.setToolTip(tooltip_text)
        if notes:
            self.notes_display.setText(notes); self.notes_display.setVisible(True)
        else:
            self.notes_display.clear(); self.notes_display.setVisible(False)
        def _format_timestamp(value):
            # Accept datetime, date, or string; return human-readable string or '-'
            try:
                if value is None:
                    return '-'
                # If it's a datetime-like object
                if hasattr(value, 'isoformat'):
                    iso_str = value.isoformat()
                    base_str = iso_str.split('.')[0]
                    qdt = QDateTime.fromString(base_str, "yyyy-MM-ddTHH:mm:ss")
                    return qdt.toString("yyyy-MM-dd HH:mm:ss") if qdt.isValid() else str(value)
                # If it's already a string
                if isinstance(value, str):
                    base_str = value.split('.')[0]
                    qdt = QDateTime.fromString(base_str, "yyyy-MM-ddTHH:mm:ss")
                    return qdt.toString("yyyy-MM-dd HH:mm:ss") if qdt.isValid() else (value or '-')
                # Fallback
                return str(value)
            except Exception:
                return '-' if not value else str(value)

        self.created_value.setText(_format_timestamp(created_at))
        self.updated_value.setText(_format_timestamp(updated_at))

    def clear_details(self):
        self.detail_site_name.setText("No item selected");
        self.detail_icon.setPixmap(QPixmap());
        self.username_value.clear();
        self.password_value.clear();
        self.website_value.clear();
        self.category_value.setText("-");
        self.notes_display.clear();
        self.notes_display.setVisible(False);
        self.created_value.setText("-");
        self.updated_value.setText("-");
        self.detail_strength_label.setText("Strength: N/A");
        self.detail_strength_label.setToolTip("")
        self.detail_stack.setCurrentIndex(0)
        self.edit_action.setEnabled(False);
        self.delete_action.setEnabled(False);
        self.copy_user_action.setEnabled(False);
        self.copy_pass_action.setEnabled(False)

    def toggle_password_visibility_detail(self, checked):
        self.password_value.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def copy_username(self):
        if self.is_locked: return
        self.copy_to_clipboard(self.username_value.text(), "Username")

    def copy_password(self):
        if self.is_locked: return
        current_item = self.password_list.currentItem();
        if not current_item: return
        entry_id = current_item.data(Qt.UserRole);
        details = self.db.get_password_details(entry_id)
        if not details or not self.cipher: return
        try:
            dec_bytes = decrypt_data(details[3], self.cipher)
            if dec_bytes:
                self.copy_to_clipboard(dec_bytes.decode('utf-8'), "Password")
            else:
                print("Failed to decrypt password")  # Quick debug print
                self.statusBar().showMessage("Failed to decrypt password for copying", 3000)
        except Exception as e:
            # Oops, something went wrong
            log.error(f"Error copying password: {str(e)}")
            self.statusBar().showMessage("Error copying password", 3000)

    def copy_website(self):
        if self.is_locked: return
        website = self.website_value.text()
        if website and website != '-': self.copy_to_clipboard(website, "Website URL")

    def copy_to_clipboard(self, text: str, item_name: str):
        if not text: self.statusBar().showMessage(f"{item_name} is empty.", 3000); return
        if pyperclip:
            copy_to_clipboard_timed(text, self.clipboard_clear_timeout)
            self.statusBar().showMessage(f"{item_name} copied (clears in {self.clipboard_clear_timeout}s)", 5000)
        else:
            self.statusBar().showMessage("pyperclip not installed.", 5000)

    def open_website(self):
        if self.is_locked: return
        url_str = self.website_value.text()
        if url_str and url_str != '-':
            try:
                url = QUrl.fromUserInput(url_str)
                if url.isValid():
                    QDesktopServices.openUrl(url)
                    self.statusBar().showMessage(f"Opening {url.toString()}...", 3000)
                else:
                    # Invalid URL format
                    self.statusBar().showMessage(f"Invalid URL: {url_str}", 3000)
            except:
                # Something went wrong opening the URL
                self.statusBar().showMessage("Couldn't open website", 3000)

    def add_password(self):
        if self.is_locked or not self.cipher:
            QMessageBox.critical(self, "Error", "Vault locked or key missing.")
            return

        # Get categories from both database and custom categories
        db_categories = self.db.get_all_categories()
        custom_categories = self.load_custom_categories()
        all_categories = sorted(list(set(db_categories + custom_categories)))

        dialog = AddEditPasswordDialog(self, db_manager=self.db, current_categories=all_categories)
        if dialog.exec_() == QDialog.Accepted:
            values = dialog.get_values()
            if not values:
                return

            # If the category is new, add it to custom categories
            if values['category'] not in db_categories and values['category'] != 'Uncategorized':
                custom_categories.append(values['category'])
                self.save_custom_categories(custom_categories)

            encrypted = encrypt_data(values['password'].encode('utf-8'), self.cipher)
            if not encrypted:
                QMessageBox.critical(self, "Encryption Error", "Failed to encrypt password!")
                return

            new_id = self.db.add_password(values['site'], values['username'], encrypted, values['website'],
                                          values['category'], values['notes'])
            if new_id is not None:
                self.load_passwords()
                self.load_categories_into_sidebar()
                self.statusBar().showMessage("Password added successfully!", 3000)
            elif new_id is None and values:
                QMessageBox.warning(self, "Duplicate Entry",
                                    f"Entry for '{values['site']}' / '{values['username']}' already exists.")
            else:
                QMessageBox.critical(self, "Database Error", "Failed to add password!")

    def edit_password(self):
        if self.is_locked:
            return

        current_item = self.password_list.currentItem()
        if not current_item or not self.cipher:
            return

        entry_id = current_item.data(Qt.UserRole)
        db_entry_data = self.db.get_password_details(entry_id)
        if not db_entry_data:
            QMessageBox.critical(self, "Error", "Could not retrieve entry details.")
            return

        entry_data = {
            'id': db_entry_data[0],
            'site': db_entry_data[1],
            'username': db_entry_data[2],
            'encrypted_password': db_entry_data[3],
            'website': db_entry_data[4],
            'category': db_entry_data[5],
            'notes': db_entry_data[6]
        }

        # Get categories from both database and custom categories
        db_categories = self.db.get_all_categories()
        custom_categories = self.load_custom_categories()
        all_categories = sorted(list(set(db_categories + custom_categories)))

        dialog = AddEditPasswordDialog(self, db_manager=self.db, current_categories=all_categories,
                                       entry_data=entry_data)
        if dialog.exec_() == QDialog.Accepted:
            new_values = dialog.get_values()
            if not new_values:
                return

            # If the category is new, add it to custom categories
            if new_values['category'] not in db_categories and new_values['category'] != 'Uncategorized':
                custom_categories.append(new_values['category'])
                self.save_custom_categories(custom_categories)

            encrypted = encrypt_data(new_values['password'].encode('utf-8'), self.cipher)
            if not encrypted:
                QMessageBox.critical(self, "Encryption Error", "Failed to encrypt password!")
                return

            if self.db.update_password(entry_id, new_values['site'], new_values['username'], encrypted,
                                       new_values['website'], new_values['category'], new_values['notes']):
                self.load_passwords()
                self.load_categories_into_sidebar()
                self.select_item_by_id(entry_id)
                self.statusBar().showMessage("Password updated successfully!", 3000)
            else:
                QMessageBox.critical(self, "Database Error",
                                     "Failed to update password! Check for duplicate site/username.")

    def delete_password(self):
        if self.is_locked: return
        current_item = self.password_list.currentItem();
        if not current_item: return
        entry_id = current_item.data(Qt.UserRole);
        details = self.db.get_password_details(entry_id)
        site_name = details[1] if details else "this entry"
        reply = QMessageBox.warning(self, "Confirm Deletion", f"Delete password for '{site_name}'?",
                                    QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if reply == QMessageBox.Yes:
            if self.db.delete_password(entry_id):
                self.load_passwords();
                self.clear_details();
                self.load_categories_into_sidebar()
                self.statusBar().showMessage("Password deleted successfully!", 3000)
            else:
                QMessageBox.critical(self, "Database Error", "Failed to delete password!")

    def change_master_password(self):
        if self.is_locked or not self.cipher or not self.current_master_hash or not self.current_salt:
            QMessageBox.warning(self, "Vault Locked/Invalid State", "Unlock vault first.");
            return
        current_dialog = PasswordDialog(self, "Enter CURRENT master password:")
        if current_dialog.exec_() != QDialog.Accepted or not verify_password(current_dialog.get_password(),
                                                                             self.current_master_hash,
                                                                             self.current_salt):
            QMessageBox.warning(self, "Error", "Incorrect current master password!");
            return
        new_dialog = PasswordDialog(self, "Enter NEW master password:", is_confirmation=True,
                                    title="Set New Master Password")
        if new_dialog.exec_() != QDialog.Accepted: return
        new_password = new_dialog.get_password()
        if not new_password or new_password == current_dialog.get_password():
            QMessageBox.warning(self, "Error", "New password invalid or same as old.");
            return
        log.info("Starting master password change. Re-encryption required.")
        progress = QProgressDialog("Re-encrypting vault data...", "Cancel", 0, 100, self);
        progress.setWindowModality(Qt.WindowModal);
        progress.setWindowTitle("Changing Master Password");
        progress.show();
        QApplication.processEvents()
        new_hash, new_salt = hash_password(new_password)
        try:
            new_key = generate_encryption_key_from_password(new_password, new_salt); new_cipher = Fernet(new_key)
        except Exception as e:
            log.error(f"Failed to derive new key: {e}"); QMessageBox.critical(self, "Encryption Error",
                                                                              f"Failed: {e}"); progress.close(); return
        success, old_cipher = True, self.cipher;
        all_entries = self.db.get_all_passwords();
        total_entries = len(all_entries);
        progress.setRange(0, total_entries + 2)
        for i, entry_summary in enumerate(all_entries):
            entry_id = entry_summary[0];
            progress.setValue(i);
            progress.setLabelText(f"Re-encrypting entry {i + 1}/{total_entries}...")
            if progress.wasCanceled(): log.warning("MP change cancelled."); QMessageBox.warning(self, "Cancelled",
                                                                                                "MP change cancelled."); success = False; break
            details = self.db.get_password_details(entry_id)
            if not details: log.error(f"No details for ID {entry_id}."); success = False; break
            _id, site, user, enc_pass, web, cat, notes, _, _ = details
            dec_bytes = decrypt_data(enc_pass, old_cipher)
            if dec_bytes is None: log.error(f"Failed to decrypt ID {entry_id} old key."); success = False; break
            new_enc_pass = encrypt_data(dec_bytes, new_cipher)
            if new_enc_pass is None: log.error(f"Failed to re-encrypt ID {entry_id} new key."); success = False; break
            if not self.db.update_password(entry_id, site, user, new_enc_pass, web, cat, notes): log.error(
                f"DB update fail ID {entry_id}."); success = False; break
            QApplication.processEvents()
        if success:
            progress.setValue(total_entries);
            progress.setLabelText("Re-encrypting 2FA secret...");
            QApplication.processEvents()
            enc_secret_old = self.db.get_setting("totp_secret_encrypted")
            if enc_secret_old:
                dec_secret_bytes = decrypt_data(enc_secret_old, old_cipher)
                if dec_secret_bytes:
                    new_enc_secret = encrypt_data(dec_secret_bytes, new_cipher)
                    if new_enc_secret:
                        if not self.db.set_setting("totp_secret_encrypted", new_enc_secret): log.error(
                            "Failed save re-enc 2FA."); success = False
                    else:
                        log.error("Failed re-enc 2FA new key."); success = False
                else:
                    log.error("Failed dec existing 2FA old key."); success = False
        if success:
            progress.setValue(total_entries + 1);
            progress.setLabelText("Saving new master password...");
            QApplication.processEvents()
            if self.db.set_master_password(new_hash, new_salt):
                self.cipher = new_cipher;
                self.current_salt = new_salt;
                self.current_master_hash = new_hash;
                progress.setValue(total_entries + 2)
                log.info("Master password changed successfully.");
                QMessageBox.information(self, "Success", "Master password changed successfully!")
            else:
                log.critical("CRITICAL: Re-enc OK, BUT FAILED save new MP hash!"); QMessageBox.critical(self,
                                                                                                        "CRITICAL ERROR",
                                                                                                        "Failed to save new MP after re-enc! Backup data!"); success = False
        else:
            log.error("MP change failed during re-enc. MP NOT changed.")
            if not progress.wasCanceled(): QMessageBox.critical(self, "Error",
                                                                "MP change failed during data re-enc. MP NOT changed.")
        progress.close()

    def export_vault_triggered(self):
        if self.is_locked or not self.cipher: QMessageBox.warning(self, "Vault Locked",
                                                                  "Unlock vault before exporting."); return
        filepath, _ = QFileDialog.getSaveFileName(self, "Export Vault As...", DB_BACKUP_PATH,
                                                  "Encrypted JSON Backup (*.json.enc);;All Files (*)")
        if not filepath: return
        if export_vault(self.db.get_all_data_for_export(), filepath, self.cipher):
            self.statusBar().showMessage(f"Vault exported to {filepath}", 5000);
            QMessageBox.information(self, "Export Successful", f"Vault exported to:\n{filepath}")
        else:
            QMessageBox.critical(self, "Export Failed", "Error exporting vault.")

    def import_vault_triggered(self):
        if self.is_locked or not self.cipher: QMessageBox.warning(self, "Vault Locked",
                                                                  "Unlock vault before importing."); return
        reply = QMessageBox.warning(self, "Confirm Import",
                                    "Importing adds/updates entries. EXPORT current vault first as backup.\n\nProceed?",
                                    QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if reply != QMessageBox.Yes: return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Vault Backup", "",
                                                  "Encrypted JSON Backup (*.json.enc);;All Files (*)")
        if not filepath: return
        imported_data = import_vault(filepath, self.cipher)
        if imported_data is None: QMessageBox.critical(self, "Import Failed",
                                                       "Failed to decrypt/read import file."); return
        imported_count, failed_count = self.db.import_data(imported_data)
        if imported_count > 0 or failed_count > 0:
            self.load_passwords();
            self.load_categories_into_sidebar()
            QMessageBox.information(self, "Import Complete",
                                    f"Imported/updated: {imported_count}\nFailed: {failed_count}")
        else:
            QMessageBox.warning(self, "Import Complete", "No valid entries found in file.")

    def open_settings(self):
        if self.is_locked: QMessageBox.warning(self, "Vault Locked", "Unlock vault for settings."); return
        dialog = SettingsDialog(self, db_manager=self.db, cipher_suite=self.cipher)
        dialog.categories_updated.connect(self.handle_new_categories)
        dialog.exec_()

    def show_about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
                          f"<b>{APP_NAME} v{APP_VERSION}</b><br><br>Secure desktop password manager.<br><br>© {time.strftime('%Y')} {APP_NAME}.<br><br>DB: {DB_PATH}<br>Built with Python and PyQt5.")

    def unlock_vault(self):
        if not self.is_locked: return
        log.info("Unlock action triggered.")
        if self.login("Enter master password to unlock:"):  # Update UI only happens in __init__ after init_ui
            self.update_lock_status_ui()  # Now safe to call to reflect unlocked state
            self.load_passwords()
            self.load_categories_into_sidebar()

    def lock_vault(self):
        if self.is_locked: return
        log.info("Locking vault.")
        self.is_locked = True;
        self.cipher = None
        self.clear_details();
        self.password_list.clear();
        self.search_edit.clear()
        self.update_lock_status_ui();
        self.inactivity_timer.stop()

    def update_lock_status_ui(self):
        locked = self.is_locked
        if hasattr(self, 'central_widget_stack'):  # Check if UI elements exist
            self.central_widget_stack.setCurrentIndex(1 if locked else 0)
            self.add_action.setEnabled(not locked);
            self.import_action.setEnabled(not locked);
            self.export_action.setEnabled(not locked)
            self.lock_action.setEnabled(not locked);
            self.unlock_action.setEnabled(locked)
            self.statusBar().showMessage("Vault Locked" if locked else "Vault Unlocked", 0)
        self.lock_status_changed.emit(locked)

    def select_item_by_id(self, entry_id: int):
        for i in range(self.password_list.count()):
            item = self.password_list.item(i)
            if item and item.data(Qt.UserRole) == entry_id:
                self.password_list.setCurrentItem(item);
                self.password_list.scrollToItem(item);
                break

    def show_list_context_menu(self, position):
        """Show context menu for password list items."""
        menu = QMenu()

        # Get selected items
        selected_items = self.password_list.selectedItems()
        if not selected_items:
            return

        # Add standard actions
        if len(selected_items) == 1:
            menu.addAction("Edit", self.edit_password)
            menu.addAction("Delete", self.delete_password)
            menu.addSeparator()
            menu.addAction("Copy Username", self.copy_username)
            menu.addAction("Copy Password", self.copy_password)
            menu.addAction("Copy Website", self.copy_website)
            menu.addAction("Open Website", self.open_website)
        else:
            # Multiple items selected
            menu.addAction("Delete Selected", self.delete_password)
            menu.addSeparator()
            menu.addAction("Merge Selected", self.merge_selected_passwords)

        menu.exec_(self.password_list.mapToGlobal(position))

    def merge_selected_passwords(self):
        """Merge multiple selected password entries into one."""
        if self.is_locked:
            QMessageBox.warning(self, "Vault Locked", "Please unlock the vault first.")
            return

        selected_items = self.password_list.selectedItems()
        if len(selected_items) < 2:
            QMessageBox.warning(self, "Selection Required", "Please select at least 2 entries to merge.")
            return

        # Get all selected entries
        entries = []
        for item in selected_items:
            entry_id = item.data(Qt.UserRole)
            details = self.db.get_password_details(entry_id)
            if details:
                entries.append({
                    'id': details[0],
                    'site': details[1],
                    'username': details[2],
                    'website': details[4],
                    'category': details[5]
                })

        # Group entries by site
        site_groups = {}
        for entry in entries:
            site = entry['site'].lower()  # Case-insensitive grouping
            if site not in site_groups:
                site_groups[site] = []
            site_groups[site].append(entry)

        # Find groups with multiple entries
        mergeable_groups = {site: entries for site, entries in site_groups.items() if len(entries) > 1}

        if not mergeable_groups:
            QMessageBox.information(self, "No Mergeable Entries",
                                    "No entries with the same site name were found in the selection.")
            return

        # Create merge dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Merge Password Entries")
        layout = QVBoxLayout(dialog)

        # Add explanation
        layout.addWidget(QLabel("Select which entry to keep for each site:"))

        # Create group boxes for each site
        group_selections = {}  # Store the selected target IDs
        for site, entries in mergeable_groups.items():
            group_box = QGroupBox(f"Site: {entries[0]['site']}")
            group_layout = QVBoxLayout()

            # Create radio buttons for each entry
            button_group = QButtonGroup()
            for entry in entries:
                radio = QRadioButton(f"Username: {entry['username']}")
                if entry.get('website'):
                    radio.setToolTip(f"Website: {entry['website']}")
                radio.setProperty('entry_id', entry['id'])
                button_group.addButton(radio)
                group_layout.addWidget(radio)

            # Select the first entry by default
            if button_group.buttons():
                button_group.buttons()[0].setChecked(True)
                group_selections[site] = button_group.buttons()[0].property('entry_id')

            # Store the selection when changed
            button_group.buttonClicked.connect(
                lambda btn, s=site: group_selections.update({s: btn.property('entry_id')})
            )

            group_box.setLayout(group_layout)
            layout.addWidget(group_box)

        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec_() == QDialog.Accepted:
            # Perform the merges
            for site, target_id in group_selections.items():
                source_ids = [entry['id'] for entry in mergeable_groups[site] if entry['id'] != target_id]
                if self.db.merge_passwords(target_id, source_ids):
                    self.statusBar().showMessage(f"Successfully merged entries for {site}", 3000)
                else:
                    QMessageBox.warning(self, "Merge Error",
                                        f"Failed to merge entries for {site}. Please try again.")

            # Refresh the password list
            self.load_passwords()
            self.load_categories_into_sidebar()

    def closeEvent(self, event):
        log.info("Close event triggered.")
        if not self.is_locked: self.lock_vault()
        event.accept()

    def handle_new_categories(self, new_categories):
        """Update the sidebar with newly created categories from the settings dialog."""
        if not new_categories:
            return

        # Add each new category to the sidebar
        for category in new_categories:
            if category != 'Uncategorized':
                cat_item = QListWidgetItem(category)
                try:
                    cat_item.setIcon(qta.icon('fa5s.folder-open', color='lightgray'))
                except Exception:
                    pass
                cat_item.setData(Qt.UserRole, f"category_{category}")
                self.filter_list.addItem(cat_item)

        # Log the update
        log.info(f"Added {len(new_categories)} new categories to sidebar")

        # Save custom categories to QSettings
        self.save_custom_categories()

    def save_custom_categories(self, categories=None):
        """Save custom categories to QSettings (those that aren't yet in the database)"""
        if self.is_locked:
            return

        # If no categories provided, get them from the sidebar
        if categories is None:
            custom_categories = []
            for i in range(self.filter_list.count()):
                item = self.filter_list.item(i)
                if item and item.data(Qt.UserRole) and item.data(Qt.UserRole).startswith("category_"):
                    category = item.data(Qt.UserRole).split("_", 1)[1]
                    if category != "Uncategorized":
                        custom_categories.append(category)
        else:
            custom_categories = categories

        # Get existing db categories
        db_categories = self.db.get_all_categories()

        # Get categories that are custom only (not in database)
        custom_only = [c for c in custom_categories if c not in db_categories]

        # Save to QSettings
        settings = QSettings()
        settings.setValue("categories/custom_categories", custom_only)
        log.info(f"Saved {len(custom_only)} custom categories to settings")


class EmailSenderThread(QThread):
    result = pyqtSignal(bool, str)
    def __init__(self, recipient_email, otp_code, subject, parent=None):
        super().__init__(parent)
        self.recipient_email = recipient_email
        self.otp_code = otp_code
        self.subject = subject
    def run(self):
        from utils import send_otp_email
        try:
            ok = send_otp_email(self.recipient_email, self.otp_code, subject=self.subject)
            self.result.emit(ok, "")
        except Exception as e:
            self.result.emit(False, str(e))


if __name__ == "__main__":
    # Ensure QApplication is created first
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("YourCompanyName")  # Optional, used by QSettings

    # Set application style (Fusion is good cross-platform)
    app.setStyle("Fusion")

    # Apply a dark color palette (example, customize as needed)
    # (Using a predefined dark palette for simplicity)
    try:
        import darkdetect  # pip install darkdetect

        if darkdetect.isDark():
            # Use a dark style sheet or palette if system is dark
            # Example using qdarkstyle: pip install qdarkstyle
            try:
                import qdarkstyle

                app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            except ImportError:
                log.warning("qdarkstyle not found. Using default Fusion style.")
                # Or apply manual palette
                # palette = QPalette() ... (set colors) ... app.setPalette(palette)
        else:
            log.info("Light mode detected. Using default Fusion style.")

    except ImportError:
        log.info("darkdetect not found. Using default Fusion style.")

    # Start the application
    try:
        window = PasswordManagerGUI()
        # Only show if init didn't fail
        if hasattr(window, 'is_locked'):  # Check if init_ui was likely reached
            window.show()
            sys.exit(app.exec_())
        else:
            # Exit if setup/login failed before window creation
            log.critical("Application initialization failed. Exiting.")
            sys.exit(1)
    except Exception as e:
        # Catch any unexpected errors during initialization or runtime
        # Ensure log is defined, or use print for this critical fallback
        if 'log' in globals():
            log.critical(f"Unhandled exception occurred: {e}", exc_info=True)
        else:
            print(f"CRITICAL UNHANDLED EXCEPTION (logging not initialized): {e}")
            import traceback

            traceback.print_exc()

        # Show error message to user
        error_dialog = QMessageBox()
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setWindowTitle("Fatal Error")
        error_dialog.setText("A critical error occurred and the application must close.")

        # Safely construct the detailed text for LOG_PATH
        log_path_message_segment = "\n\nCheck the log file for more details"
        try:
            # LOG_PATH should be available if imports at the top of Main.py succeeded
            log_path_message_segment += f":\n{str(LOG_PATH)}"
        except NameError:
            log_path_message_segment += " (Log path configuration not found)."
        except Exception as log_e:
            log_path_message_segment += f" (Error accessing log path: {str(log_e)})."

        error_dialog.setDetailedText(str(e) + log_path_message_segment)
        error_dialog.exec_()
        sys.exit(1)