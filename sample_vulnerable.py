#!/usr/bin/env python3
"""
Sample vulnerable Python file for testing the security scanner.
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import subprocess
import random
import hashlib
import pickle
import yaml

# VULNERABILITY 1: Hardcoded sensitive information
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
SECRET_TOKEN = "super_secret_token_123"


# Placeholder function for database operations
def execute_query(query):
    """Placeholder function - would execute SQL in real code"""
    print(f"Executing query: {query}")
    return []


# VULNERABILITY 2: SQL Injection
def get_user_data(user_id):
    """Vulnerable to SQL injection"""
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    # This is vulnerable to SQL injection attacks
    return execute_query(query)


def search_products(search_term):
    """Another SQL injection vulnerability"""
    sql = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return execute_query(sql)


# VULNERABILITY 3: Command Injection
def run_system_command(user_input):
    """Vulnerable to command injection"""
    command = f"ls -la {user_input}"
    os.system(command)  # NEVER do this with user input!


def backup_file(filename):
    """Another command injection vulnerability"""
    subprocess.call(f"cp {filename} /backup/", shell=True)


# VULNERABILITY 4: Insecure random number generation
def generate_token():
    """Insecure random token generation"""
    return str(random.random())  # Use secrets module instead


def create_session_id():
    """Another insecure random example"""
    return random.randint(1000, 9999)


# VULNERABILITY 5: Weak cryptographic practices
def hash_password(password):
    """Weak password hashing"""
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is broken!


def simple_encrypt(data):
    """Terrible encryption"""
    key = "1234"  # Hardcoded key
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))


# VULNERABILITY 6: Unsafe deserialization
def load_user_data(serialized_data):
    """Vulnerable to pickle attacks"""
    return pickle.loads(serialized_data)  # NEVER unpickle untrusted data!


def load_config(yaml_data):
    """Unsafe YAML loading"""
    return yaml.load(yaml_data, Loader=yaml.FullLoader)  # Should use yaml.safe_load()


# VULNERABILITY 7: Path traversal
def read_user_file(filename):
    """Vulnerable to path traversal"""
    file_path = f"/home/user/files/{filename}"
    with open(file_path, "r") as f:  # No path validation!
        return f.read()


def save_upload(filename, content):
    """Another path traversal vulnerability"""
    with open(f"uploads/{filename}", "w") as f:
        f.write(content)


# VULNERABILITY 8: Information disclosure
def debug_info():
    """Exposes sensitive debug information"""
    return {
        "database_host": "prod-db-01.internal.company.com",
        "api_keys": [API_KEY, "another-secret-key"],
        "environment": "production",
        "debug_mode": True,
    }


# VULNERABILITY 9: Unsafe file operations
def process_file(filepath):
    """Unsafe file operations"""
    os.chmod(filepath, 0o777)  # Too permissive permissions


def create_temp_file():
    """Insecure temp file creation"""
    import tempfile

    fd, path = tempfile.mkstemp()  # Should set secure permissions
    return path


# VULNERABILITY 10: XML External Entity (XXE)
def parse_xml(xml_data):
    """Vulnerable to XXE attacks"""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_data)  # Should disable external entities
    return root


# VULNERABILITY 11: Server-Side Request Forgery (SSRF)
def fetch_url(url):
    """Vulnerable to SSRF"""
    import urllib.request

    return urllib.request.urlopen(url).read()  # No URL validation!


# VULNERABILITY 12: Insecure direct object references
class UserManager:
    def get_user_profile(self, user_id):
        """No authorization check"""
        return f"SELECT * FROM profiles WHERE user_id = {user_id}"

    def delete_user(self, user_id):
        """Dangerous operation without authorization"""
        return f"DELETE FROM users WHERE id = {user_id}"


# VULNERABILITY 13: Weak session management
SESSION_STORE = {}


def create_session(username):
    """Weak session management"""
    session_id = str(hash(username))  # Predictable session ID
    SESSION_STORE[session_id] = username
    return session_id


# VULNERABILITY 14: Insufficient logging
def transfer_money(from_account, to_account, amount):
    """Financial operation without proper logging"""
    # No audit trail for sensitive operations
    return f"Transferred ${amount} from {from_account} to {to_account}"


# VULNERABILITY 15: Hardcoded crypto keys
ENCRYPTION_KEY = b"1234567890123456"  # 16 bytes for AES-128


def encrypt_data(data):
    """Hardcoded encryption key"""
    from cryptography.fernet import Fernet
    import base64

    key = base64.urlsafe_b64encode(ENCRYPTION_KEY)
    f = Fernet(key)
    return f.encrypt(data.encode())


if __name__ == "__main__":
    print("This is a vulnerable file for security testing purposes.")
    print("It contains multiple security vulnerabilities intentionally.")
    print("Scanner should detect issues like:")
    print("- Hardcoded secrets")
    print("- SQL injection vulnerabilities")
    print("- Command injection flaws")
    print("- Weak cryptography")
    print("- Unsafe deserialization")
    print("- Path traversal vulnerabilities")
    print("- And many more security issues!")
