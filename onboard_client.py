import os
import json
import base64
from datetime import datetime, timezone
# Removed: from google.cloud import secretmanager
from airtable import Airtable
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.exceptions import InvalidSignature, InvalidTag
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration and Setup ---

def load_config():
    """Loads configuration from environment variables."""
    config = {
        "encryption_key": os.environ.get("ENCRYPTION_KEY"), # Read encryption key from env var
        "airtable_api_key": os.environ.get("AIRTABLE_API_KEY"),
        "airtable_base_id": os.environ.get("AIRTABLE_BASE_ID"),
        "airtable_table_name": os.environ.get("AIRTABLE_TABLE_NAME"),
    }
    if not all(config.values()):
        missing_vars = [k for k, v in config.items() if v is None]
        raise ValueError(f"Missing one or more required environment variables: {', '.join(missing_vars)}. Check your .env file or environment settings.")

    # Validate encryption key length and decode
    try:
        # The encryption key from environment variable must be exactly 32 bytes for AES-256
        encryption_key_bytes = base64.b64decode(config["encryption_key"])
        if len(encryption_key_bytes) != 32:
             raise ValueError(f"Encryption key must be 32 bytes long for AES-256, but got {len(encryption_key_bytes)} bytes after base64 decoding. Check your ENCRYPTION_KEY environment variable.")
        config["encryption_key_bytes"] = encryption_key_bytes
    except Exception as e:
         raise ValueError(f"Invalid ENCRYPTION_KEY format. Must be a valid base64 encoded 32-byte key: {e}") from e

    return config

# Removed: --- Google Secret Manager Interaction ---

# Removed: def get_secret(project_id: str, secret_name: str):
# Removed:     """Fetches the latest version of a secret from Google Secret Manager."""
# Removed:     client = secretmanager.SecretManagerServiceClient()
# Removed:     # Build the resource name of the secret version.
# Removed:     name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
# Removed:     try:
# Removed:         response = client.access_secret_version(request={"name": name})
# Removed:         # Return the secret payload as a string. Secrets are bytes.
# Removed:         return response.payload.data
# Removed:     except Exception as e:
# Removed:         print(f"Error fetching secret from Google Secret Manager: {e}")
# Removed:         raise

# --- Encryption/Decryption ---

def encrypt_data(data: str, key: bytes):
    """Encrypts data using AES-256-GCM."""
    backend = default_backend()
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    return base64.b64encode(nonce + ciphertext + tag).decode('utf-8')

# --- Airtable Interaction ---

def connect_airtable(api_key: str, base_id: str, table_name: str):
    """Connects to the specified Airtable table."""
    try:
        return Airtable(base_id, table_name, api_key)
    except Exception as e:
        print(f"Error connecting to Airtable: {e}")
        raise

def update_client_credentials_by_location_id(config, encryption_key: bytes, location_id: str, client_secret: str, refresh_token: str):
    """
    Finds an Airtable record by locationId, encrypts client credentials, and updates the record.
    """
    airtable_client = connect_airtable(config["airtable_api_key"], config["airtable_base_id"], config["airtable_table_name"])

    try:
        print(f"Searching for record with locationId: {location_id}")
        # Search for the record by locationId
        # The search method returns a list of records matching the criteria
        records = airtable_client.search('locationId', location_id)

        if not records:
            print(f"No record found with locationId: {location_id}.")
            print("Please ensure a record with this locationId exists in Airtable.")
            return # Exit the function if no record is found

        # Assuming locationId is unique and the first result is the correct one
        record_to_update = records[0]
        record_id = record_to_update['id']

        print(f"Found record {record_id} for locationId: {location_id}. Encrypting and updating credentials...")

        # Encrypt sensitive credentials
        encrypted_secret = encrypt_data(client_secret, encryption_key)
        encrypted_refresh = encrypt_data(refresh_token, encryption_key)

        # Prepare data for update
        update_data = {
            'encrypted_secret': encrypted_secret,
            'encrypted_refresh': encrypted_refresh,
            # Note: We are NOT updating client_id or creating a new record.
            # Ensure locationId is already present in the record in Airtable.
        }

        # Update the existing record in Airtable
        airtable_client.update(record_id, update_data)
        print(f"Successfully updated record {record_id} for locationId {location_id} with encrypted credentials.")

    except Exception as e:
        print(f"Error updating credentials for locationId {location_id}: {e}")
        raise

# --- Main Execution for Onboarding ---

if __name__ == "__main__":
    try:
        print("Starting client credential update process by locationId...")
        config = load_config()

        # 1. Load config and encryption key from environment variables
        encryption_key_bytes = config["encryption_key_bytes"]
        print("Encryption key loaded from environment variable.")

        # 2. Prompt user for client details
        location_id = input("Enter locationId of the record to update: ")
        client_secret = input("Enter client_secret: ")

        # Read refresh token from file
        refresh_token_file = "refresh_token.txt"
        try:
            with open(refresh_token_file, 'r') as f:
                refresh_token = f.read().strip()
            print(f"Read refresh token from {refresh_token_file}")
        except FileNotFoundError:
            print(f"Error: {refresh_token_file} not found.")
            print("Please create a file named 'refresh_token.txt' in the same directory as the script and paste the refresh token inside it.")
            exit(1)
        except Exception as e:
            print(f"Error reading refresh token from {refresh_token_file}: {e}")
            exit(1)

        # 3. Update the client credentials in the found record
        update_client_credentials_by_location_id(config, encryption_key_bytes, location_id, client_secret, refresh_token)

        print("Client credential update process completed.")

    except ValueError as ve:
        print(f"Configuration Error: {ve}")
        exit(1)
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        exit(1)
