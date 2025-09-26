import logging
import os
from typing import List, Tuple, Optional, Dict, Any
from config import DB_PATH, DB_BACKUP_PATH, DB_ENGINE, MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
import json
from datetime import datetime

try:
    import mysql.connector  # type: ignore
    from mysql.connector import errorcode  # type: ignore
except Exception:  # mysql driver optional unless DB_ENGINE == 'mysql'
    mysql = None


class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = str(db_path)
        self.engine = DB_ENGINE
        self._init_db()

    # --- Connection helpers ---
    def _connect_mysql_server(self):
        return mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
        )

    def _connect_mysql_db(self):
        return mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
        )

    def _execute(self, sql: str, params: Tuple = (), *, fetchone: bool = False, fetchall: bool = False, dict_cursor: bool = False):
        """Execute a query with engine-aware parameter style and return results if requested."""
        # MySQL only path
        sql_to_run = sql.replace('?', '%s')
        conn = self._connect_mysql_db()
        try:
            cursor = conn.cursor(dictionary=dict_cursor)
            cursor.execute(sql_to_run, params)
            result = None
            if fetchone:
                result = cursor.fetchone()
            elif fetchall:
                result = cursor.fetchall()
            conn.commit()
            if result is None and not fetchone and not fetchall:
                result = cursor.lastrowid
            cursor.close()
            return result
        finally:
            conn.close()

    def _init_db(self):
        """Initialize the database with necessary tables if they don't exist."""
        if mysql is None:
            raise RuntimeError("MySQL driver not installed. Please install mysql-connector-python.")
        try:
            # Ensure database exists
            server_conn = self._connect_mysql_server()
            server_cursor = server_conn.cursor()
            server_cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}`")
            server_cursor.close()
            server_conn.close()

            conn = self._connect_mysql_db()
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS passwords (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    site VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    password TEXT NOT NULL,
                    website VARCHAR(512),
                    category VARCHAR(64) DEFAULT 'Uncategorized',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_site_username (site, username)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS master_password (
                    id TINYINT PRIMARY KEY,
                    hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    `key` VARCHAR(191) PRIMARY KEY,
                    `value` TEXT
                )
                """
            )
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("MySQL database initialized/connected successfully")
        except Exception as e:
            logging.error(f"MySQL initialization error: {e}")
            raise

    def add_password(self, site: str, username: str, encrypted_password: str,
                     website: Optional[str] = None, category: Optional[str] = None,
                     notes: Optional[str] = None) -> Optional[int]:
        """Add a new password entry. Returns the ID of the new entry or None on failure."""
        try:
            new_id = self._execute(
                """
                INSERT INTO passwords (site, username, password, website, category, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (site, username, encrypted_password, website, category or 'Uncategorized', notes)
            )
            logging.info(f"Added new password entry for site: {site}, ID: {new_id}")
            return int(new_id) if new_id is not None else None
        except Exception as e:
            # Handle duplicates/errors uniformly
            logging.warning(f"Failed to add entry for {site}/{username}: {e}")
            return None

    def get_password_details(self, entry_id: int) -> Optional[Tuple]:
        """Retrieve full details for a specific password entry by ID."""
        try:
            result = self._execute(
                """
                SELECT id, site, username, password, website, category, notes, created_at, updated_at
                FROM passwords
                WHERE id = ?
                """,
                (entry_id,),
                fetchone=True,
            )
            if result is None:
                return None
            # result can be sqlite3.Row, tuple, or dict depending on engine
            if isinstance(result, dict):
                created = result.get('created_at')
                updated = result.get('updated_at')
                try:
                    if hasattr(created, 'isoformat'):
                        created = created.isoformat()
                except Exception:
                    pass
                try:
                    if hasattr(updated, 'isoformat'):
                        updated = updated.isoformat()
                except Exception:
                    pass
                return (
                    result.get('id'), result.get('site'), result.get('username'), result.get('password'),
                    result.get('website'), result.get('category'), result.get('notes'),
                    created, updated
                )
            return tuple(result)
        except Exception as e:
            logging.error(f"Error retrieving password details for ID {entry_id}: {e}")
            return None

    def update_password(self, entry_id: int, site: str, username: str, encrypted_password: str,
                        website: Optional[str] = None, category: Optional[str] = None,
                        notes: Optional[str] = None) -> bool:
        """Update an existing password entry by ID."""
        try:
            # updated_at handled by ON UPDATE CURRENT_TIMESTAMP
            sql = (
                "UPDATE passwords SET site = ?, username = ?, password = ?, website = ?, "
                "category = ?, notes = ? WHERE id = ?"
            )
            self._execute(
                sql,
                (site, username, encrypted_password, website, category or 'Uncategorized', notes, entry_id)
            )
            # Determine if row exists
            exists = self.get_password_details(entry_id) is not None
            updated = exists
            if updated:
                logging.info(f"Updated password entry ID: {entry_id}")
            else:
                logging.warning(f"Attempted to update non-existent password entry ID: {entry_id}")
            return updated
        except Exception as e:
            logging.error(f"Error updating password ID {entry_id}: {e}")
            return False

    def delete_password(self, entry_id: int) -> bool:
        """Delete a password entry by ID."""
        try:
            self._execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
            # Verify deletion
            exists = self.get_password_details(entry_id)
            deleted = exists is None
            if deleted:
                logging.info(f"Deleted password entry ID: {entry_id}")
            else:
                logging.warning(f"Attempted to delete non-existent password entry ID: {entry_id}")
            return deleted
        except Exception as e:
            logging.error(f"Error deleting password ID {entry_id}: {e}")
            return False

    def get_all_passwords(self) -> List[Tuple]:
        """Retrieve essential details (id, site, username, category) for all password entries."""
        try:
            rows = self._execute(
                """
                SELECT id, site, username, category
                FROM passwords
                ORDER BY site ASC, username ASC
                """,
                (),
                fetchall=True,
            ) or []
            if rows and isinstance(rows[0], dict):
                return [(r['id'], r['site'], r['username'], r['category']) for r in rows]
            return rows
        except Exception as e:
            logging.error(f"Error retrieving all passwords: {e}")
            return []

    def search_passwords(self, query: str) -> List[Tuple]:
        """Search for password entries by site, username, or category."""
        try:
            search_query = f"%{query}%"
            rows = self._execute(
                """
                SELECT id, site, username, category
                FROM passwords
                WHERE site LIKE ? OR username LIKE ? OR category LIKE ? OR notes LIKE ? OR website LIKE ?
                ORDER BY site ASC, username ASC
                """,
                (search_query, search_query, search_query, search_query, search_query),
                fetchall=True,
            ) or []
            if rows and isinstance(rows[0], dict):
                return [(r['id'], r['site'], r['username'], r['category']) for r in rows]
            return rows
        except Exception as e:
            logging.error(f"Error searching passwords: {e}")
            return []

    def get_passwords_by_category(self, category: str) -> List[Tuple]:
        """Retrieve passwords filtered by category."""
        try:
            if category == 'All Items':
                return self.get_all_passwords()
            elif category == 'Uncategorized':
                rows = self._execute(
                    """
                    SELECT id, site, username, category
                    FROM passwords
                    WHERE category = ? OR category IS NULL OR category = ''
                    ORDER BY site ASC, username ASC
                    """,
                    (category,),
                    fetchall=True,
                ) or []
            else:
                rows = self._execute(
                    """
                    SELECT id, site, username, category
                    FROM passwords
                    WHERE category = ?
                    ORDER BY site ASC, username ASC
                    """,
                    (category,),
                    fetchall=True,
                ) or []
            if rows and isinstance(rows[0], dict):
                return [(r['id'], r['site'], r['username'], r['category']) for r in rows]
            return rows
        except Exception as e:
            logging.error(f"Error retrieving passwords for category '{category}': {e}")
            return []

    def get_all_categories(self) -> List[str]:
        """Retrieve a unique list of all categories used."""
        try:
            rows = self._execute(
                """
                SELECT DISTINCT category FROM passwords
                WHERE category IS NOT NULL AND category != ''
                ORDER BY category ASC
                """,
                (),
                fetchall=True,
            ) or []
            if rows and isinstance(rows[0], dict):
                return [r['category'] for r in rows]
            return [row[0] for row in rows]
        except Exception as e:
            logging.error(f"Error retrieving categories: {e}")
            return []

    def set_master_password(self, password_hash: str, salt: bytes) -> bool:
        """Set or update the master password."""
        try:
            sql = (
                "INSERT INTO master_password (id, hash, salt, created_at) "
                "VALUES (1, ?, ?, CURRENT_TIMESTAMP) "
                "ON DUPLICATE KEY UPDATE hash=VALUES(hash), salt=VALUES(salt), created_at=CURRENT_TIMESTAMP"
            )
            self._execute(sql, (password_hash, salt))
            logging.info("Master password set/updated successfully.")
            return True
        except Exception as e:
            logging.error(f"Error setting master password: {e}")
            return False

    def get_master_password_hash(self) -> Optional[Tuple[str, bytes]]:
        """Retrieve the master password hash and salt."""
        try:
            result = self._execute(
                "SELECT hash, salt FROM master_password WHERE id = 1",
                (),
                fetchone=True,
            )
            if not result:
                return None
            if isinstance(result, dict):
                return (result['hash'], result['salt'])
            return result
        except Exception as e:
            logging.error(f"Error retrieving master password hash: {e}")
            return None

    def set_setting(self, key: str, value: str) -> bool:
        """Set or update a setting."""
        try:
            sql = (
                "INSERT INTO settings (`key`, `value`) VALUES (?, ?) "
                "ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)"
            )
            self._execute(sql, (key, value))
            logging.info(f"Setting '{key}' updated.")
            return True
        except Exception as e:
            logging.error(f"Error setting setting '{key}': {e}")
            return False

    def get_setting(self, key: str) -> Optional[str]:
        """Retrieve a setting value."""
        try:
            result = self._execute("SELECT `value` FROM settings WHERE `key` = ?", (key,), fetchone=True)
            if not result:
                return None
            if isinstance(result, dict):
                return result.get('value')
            return result[0]
        except Exception as e:
            logging.error(f"Error retrieving setting '{key}': {e}")
            return None

    def get_all_data_for_export(self) -> Dict[str, Any]:
        """Retrieve all password data suitable for export."""
        data = {"passwords": []}
        try:
            rows = self._execute(
                "SELECT site, username, password, website, category, notes, created_at, updated_at FROM passwords",
                (),
                fetchall=True,
                dict_cursor=True,
            ) or []
            data["passwords"].extend(rows)
            return data
        except Exception as e:
            logging.error(f"Error retrieving data for export: {e}")
            return {"passwords": []}  # Return empty structure on error

    def import_data(self, data: Dict[str, Any]) -> Tuple[int, int]:
        """Import password data from a dictionary, replacing existing data."""
        imported_count = 0
        failed_count = 0
        try:
            for entry in data.get("passwords", []):
                try:
                    self._execute(
                        (
                            "INSERT INTO passwords (site, username, password, website, category, notes, created_at, updated_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                            "ON DUPLICATE KEY UPDATE password=VALUES(password), website=VALUES(website), "
                            "category=VALUES(category), notes=VALUES(notes), updated_at=VALUES(updated_at)"
                        ),
                        (
                            entry.get('site'),
                            entry.get('username'),
                            entry.get('password'),
                            entry.get('website'),
                            entry.get('category', 'Uncategorized'),
                            entry.get('notes'),
                            entry.get('created_at', datetime.now().isoformat()),
                            entry.get('updated_at', datetime.now().isoformat()),
                        )
                    )
                    imported_count += 1
                except Exception as item_error:
                    logging.error(f"Error importing item {entry.get('site')}/{entry.get('username')}: {item_error}")
                    failed_count += 1
            logging.info(f"Import completed. Imported: {imported_count}, Failed: {failed_count}")
        except Exception as e:
            logging.error(f"General error during data import: {e}")
        return imported_count, failed_count

    def get_all_encrypted_passwords(self) -> List[str]:
        """Retrieve all encrypted passwords for duplicate checking."""
        try:
            rows = self._execute("SELECT password FROM passwords", (), fetchall=True) or []
            if rows and isinstance(rows[0], dict):
                return [r['password'] for r in rows]
            return [row[0] for row in rows]
        except Exception as e:
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
            # Get target entry
            target = self._execute(
                """
                SELECT site, username, password, website, category, notes
                FROM passwords WHERE id = ?
                """,
                (target_id,),
                fetchone=True,
            )
            if not target:
                logging.error(f"Target entry {target_id} not found")
                return False
            if isinstance(target, dict):
                target_notes = target.get('notes')
            else:
                target_notes = target[5]

            if not source_ids:
                logging.error("No source entries provided")
                return False
            placeholders = ','.join(['?'] * len(source_ids))
            source_rows = self._execute(
                f"""
                SELECT id, site, username, password, website, category, notes
                FROM passwords WHERE id IN ({placeholders})
                """,
                tuple(source_ids),
                fetchall=True,
            ) or []
            if not source_rows:
                logging.error("No source entries found")
                return False

            all_notes: List[Optional[str]] = [target_notes]
            for entry in source_rows:
                if isinstance(entry, dict):
                    note_val = entry.get('notes')
                else:
                    note_val = entry[6]
                if note_val:
                    all_notes.append(note_val)
            combined_notes = "\n---\n".join(filter(None, all_notes))

            # Update target
            self._execute(
                "UPDATE passwords SET notes = ? WHERE id = ?",
                (combined_notes, target_id)
            )

            # Delete sources
            self._execute(
                f"DELETE FROM passwords WHERE id IN ({placeholders})",
                tuple(source_ids)
            )

            logging.info(f"Successfully merged {len(source_rows)} entries into entry {target_id}")
            return True
        except Exception as e:
            logging.error(f"Error merging passwords: {e}")
            return False

    def set_user_email(self, email: str) -> bool:
        """Set or update the user's email address for OTP delivery."""
        return self.set_setting("user_email", email)

    def get_user_email(self) -> Optional[str]:
        """Retrieve the user's email address for OTP delivery."""
        return self.get_setting("user_email")