import sqlite3
import logging
import os
from typing import List, Tuple, Optional, Dict, Any
from config import DB_PATH, DB_BACKUP_PATH
import json
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database with necessary tables if they don't exist."""
        # Check if DB exists and tables are present, if not, create them.
        # Avoids deleting the DB on every start unless explicitly intended.
        new_db = not os.path.exists(self.db_path)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create passwords table with additional fields
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL, -- Encrypted password
                    website TEXT,          -- URL
                    category TEXT DEFAULT 'Uncategorized',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(site, username) -- Prevent exact duplicates
                )
                """)

                # Create master_password table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """)

                # Create settings table (for 2FA secret, etc.)
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
                """)

                # Add trigger to update 'updated_at' timestamp
                cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS update_password_timestamp
                AFTER UPDATE ON passwords
                FOR EACH ROW
                BEGIN
                    UPDATE passwords SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
                END;
                """)

                conn.commit()
                if new_db:
                    logging.info("New database initialized successfully")
                else:
                    logging.info("Database connection established")
        except sqlite3.Error as e:
            logging.error(f"Database initialization/connection error: {e}")
            raise

    def add_password(self, site: str, username: str, encrypted_password: str,
                     website: Optional[str] = None, category: Optional[str] = None,
                     notes: Optional[str] = None) -> Optional[int]:
        """Add a new password entry. Returns the ID of the new entry or None on failure."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO passwords (site, username, password, website, category, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (site, username, encrypted_password, website, category or 'Uncategorized', notes))
                conn.commit()
                new_id = cursor.lastrowid
                logging.info(f"Added new password entry for site: {site}, ID: {new_id}")
                return new_id
        except sqlite3.IntegrityError:
            logging.warning(f"Attempted to add duplicate entry for site: {site}, username: {username}")
            return None  # Indicate duplicate
        except sqlite3.Error as e:
            logging.error(f"Error adding password: {e}")
            return None

    def get_password_details(self, entry_id: int) -> Optional[Tuple]:
        """Retrieve full details for a specific password entry by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row  # Return rows as dictionary-like objects
                cursor = conn.cursor()
                cursor.execute("""
                SELECT id, site, username, password, website, category, notes, created_at, updated_at
                FROM passwords
                WHERE id = ?
                """, (entry_id,))
                result = cursor.fetchone()
                return tuple(result) if result else None
        except sqlite3.Error as e:
            logging.error(f"Error retrieving password details for ID {entry_id}: {e}")
            return None

    def update_password(self, entry_id: int, site: str, username: str, encrypted_password: str,
                        website: Optional[str] = None, category: Optional[str] = None,
                        notes: Optional[str] = None) -> bool:
        """Update an existing password entry by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                UPDATE passwords
                SET site = ?, username = ?, password = ?, website = ?,
                    category = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """, (site, username, encrypted_password, website,
                      category or 'Uncategorized', notes, entry_id))

                conn.commit()
                updated = cursor.rowcount > 0
                if updated:
                    logging.info(f"Updated password entry ID: {entry_id}")
                else:
                    logging.warning(f"Attempted to update non-existent password entry ID: {entry_id}")
                return updated
        except sqlite3.IntegrityError:
            logging.warning(f"Update failed due to duplicate site/username constraint for ID: {entry_id}")
            return False
        except sqlite3.Error as e:
            logging.error(f"Error updating password ID {entry_id}: {e}")
            return False

    def delete_password(self, entry_id: int) -> bool:
        """Delete a password entry by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
                conn.commit()
                deleted = cursor.rowcount > 0
                if deleted:
                    logging.info(f"Deleted password entry ID: {entry_id}")
                else:
                    logging.warning(f"Attempted to delete non-existent password entry ID: {entry_id}")
                return deleted
        except sqlite3.Error as e:
            logging.error(f"Error deleting password ID {entry_id}: {e}")
            return False

    def get_all_passwords(self) -> List[Tuple]:
        """Retrieve essential details (id, site, username, category) for all password entries."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Only fetch necessary columns for the list view
                cursor.execute("""
                SELECT id, site, username, category
                FROM passwords
                ORDER BY site ASC, username ASC
                """)
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error retrieving all passwords: {e}")
            return []

    def search_passwords(self, query: str) -> List[Tuple]:
        """Search for password entries by site, username, or category."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                search_query = f"%{query}%"
                # Only fetch necessary columns for the list view
                cursor.execute("""
                SELECT id, site, username, category
                FROM passwords
                WHERE site LIKE ? OR username LIKE ? OR category LIKE ? OR notes LIKE ? OR website LIKE ?
                ORDER BY site ASC, username ASC
                """, (search_query, search_query, search_query, search_query, search_query))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error searching passwords: {e}")
            return []

    def get_passwords_by_category(self, category: str) -> List[Tuple]:
        """Retrieve passwords filtered by category."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if category == 'All Items':
                    return self.get_all_passwords()
                elif category == 'Uncategorized':
                    cursor.execute("""
                     SELECT id, site, username, category
                     FROM passwords
                     WHERE category = ? OR category IS NULL OR category = ''
                     ORDER BY site ASC, username ASC
                     """, (category,))
                else:
                    cursor.execute("""
                    SELECT id, site, username, category
                    FROM passwords
                    WHERE category = ?
                    ORDER BY site ASC, username ASC
                    """, (category,))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error retrieving passwords for category '{category}': {e}")
            return []

    def get_all_categories(self) -> List[str]:
        """Retrieve a unique list of all categories used."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT DISTINCT category FROM passwords
                WHERE category IS NOT NULL AND category != ''
                ORDER BY category ASC
                """)
                # Flatten the list of tuples
                categories = [row[0] for row in cursor.fetchall()]
                return categories
        except sqlite3.Error as e:
            logging.error(f"Error retrieving categories: {e}")
            return []

    def set_master_password(self, password_hash: str, salt: bytes) -> bool:
        """Set or update the master password."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Use INSERT OR REPLACE (UPSERT)
                cursor.execute("""
                INSERT OR REPLACE INTO master_password (id, hash, salt, created_at)
                VALUES (1, ?, ?, CURRENT_TIMESTAMP)
                """, (password_hash, salt))
                conn.commit()
                logging.info("Master password set/updated successfully.")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error setting master password: {e}")
            return False

    def get_master_password_hash(self) -> Optional[Tuple[str, bytes]]:
        """Retrieve the master password hash and salt."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT hash, salt FROM master_password WHERE id = 1")
                result = cursor.fetchone()
                return result if result else None
        except sqlite3.Error as e:
            logging.error(f"Error retrieving master password hash: {e}")
            return None

    def set_setting(self, key: str, value: str) -> bool:
        """Set or update a setting."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
                conn.commit()
                logging.info(f"Setting '{key}' updated.")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error setting setting '{key}': {e}")
            return False

    def get_setting(self, key: str) -> Optional[str]:
        """Retrieve a setting value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
            logging.error(f"Error retrieving setting '{key}': {e}")
            return None

    def get_all_data_for_export(self) -> Dict[str, Any]:
        """Retrieve all password data suitable for export."""
        data = {"passwords": []}
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT site, username, password, website, category, notes, created_at, updated_at FROM passwords")
                rows = cursor.fetchall()
                for row in rows:
                    data["passwords"].append(dict(row))
            return data
        except sqlite3.Error as e:
            logging.error(f"Error retrieving data for export: {e}")
            return {"passwords": []}  # Return empty structure on error

    def import_data(self, data: Dict[str, Any]) -> Tuple[int, int]:
        """Import password data from a dictionary, replacing existing data."""
        imported_count = 0
        failed_count = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Clear existing passwords before import (optional, depends on desired behavior)
                # cursor.execute("DELETE FROM passwords")
                # logging.info("Cleared existing passwords before import.")

                for entry in data.get("passwords", []):
                    try:
                        # Ensure all expected keys are present, provide defaults if missing
                        cursor.execute("""
                        INSERT INTO passwords (site, username, password, website, category, notes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(site, username) DO UPDATE SET
                        password=excluded.password,
                        website=excluded.website,
                        category=excluded.category,
                        notes=excluded.notes,
                        updated_at=excluded.updated_at
                        """, (
                            entry.get('site'),
                            entry.get('username'),
                            entry.get('password'),  # Assume already encrypted in import file
                            entry.get('website'),
                            entry.get('category', 'Uncategorized'),
                            entry.get('notes'),
                            entry.get('created_at', datetime.now().isoformat()),
                            entry.get('updated_at', datetime.now().isoformat())
                        ))
                        imported_count += 1
                    except sqlite3.Error as item_error:
                        logging.error(f"Error importing item {entry.get('site')}/{entry.get('username')}: {item_error}")
                        failed_count += 1
                conn.commit()
                logging.info(f"Import completed. Imported: {imported_count}, Failed: {failed_count}")
        except sqlite3.Error as e:
            logging.error(f"General error during data import: {e}")
            # Potentially rollback or handle partial import
        return imported_count, failed_count

    def get_all_encrypted_passwords(self) -> List[str]:
        """Retrieve all encrypted passwords for duplicate checking."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM passwords")
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error retrieving all encrypted passwords: {e}")
            return []

    def merge_passwords(self, target_id: int, source_ids: List[int]) -> bool:
        """Merge multiple password entries into one, keeping the target entry and deleting the source entries.

        Args:
            target_id: The ID of the entry to keep
            source_ids: List of IDs of entries to merge and delete

        Returns:
            bool: True if merge was successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get the target entry details
                cursor.execute("""
                SELECT site, username, password, website, category, notes
                FROM passwords WHERE id = ?
                """, (target_id,))
                target_entry = cursor.fetchone()
                if not target_entry:
                    logging.error(f"Target entry {target_id} not found")
                    return False

                # Get all source entries
                placeholders = ','.join('?' * len(source_ids))
                cursor.execute(f"""
                SELECT id, site, username, password, website, category, notes
                FROM passwords WHERE id IN ({placeholders})
                """, source_ids)
                source_entries = cursor.fetchall()

                if not source_entries:
                    logging.error("No source entries found")
                    return False

                # Combine notes from all entries
                all_notes = [target_entry[5]]  # Start with target notes
                for entry in source_entries:
                    if entry[6]:  # If source has notes
                        all_notes.append(entry[6])

                combined_notes = "\n---\n".join(filter(None, all_notes))

                # Update the target entry with combined notes
                cursor.execute("""
                UPDATE passwords
                SET notes = ?
                WHERE id = ?
                """, (combined_notes, target_id))

                # Delete the source entries
                cursor.execute(f"""
                DELETE FROM passwords
                WHERE id IN ({placeholders})
                """, source_ids)

                conn.commit()
                logging.info(f"Successfully merged {len(source_entries)} entries into entry {target_id}")
                return True

        except sqlite3.Error as e:
            logging.error(f"Error merging passwords: {e}")
            return False

    def set_user_email(self, email: str) -> bool:
        """Set or update the user's email address for OTP delivery."""
        return self.set_setting("user_email", email)

    def get_user_email(self) -> Optional[str]:
        """Retrieve the user's email address for OTP delivery."""
        return self.get_setting("user_email")