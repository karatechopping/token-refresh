import os
import json
import base64
from datetime import datetime, timedelta, timezone
import requests # Added for making HTTP requests
# Removed: from google.cloud import secretmanager
from airtable import Airtable
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.exceptions import InvalidSignature, InvalidTag
from dotenv import load_dotenv # Added to load .env file

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

    # Validate encryption key length
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

# Using AES-256-GCM for authenticated encryption
# Key should be 32 bytes for AES-256

def encrypt_data(data: str, key: bytes):
    """Encrypts data using AES-256-GCM."""
    backend = default_backend()
    # GCM requires a unique nonce for each encryption operation
    nonce = os.urandom(12) # AES-GCM recommended nonce size is 12 bytes
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    # The tag is automatically calculated and available after finalize
    tag = encryptor.tag
    # Store nonce, ciphertext, and tag together
    return base64.b64encode(nonce + ciphertext + tag).decode('utf-8')

def decrypt_data(encrypted_data: str, key: bytes):
    """Decrypts data using AES-256-GCM."""
    backend = default_backend()
    decoded_data = base64.b64decode(encrypted_data)
    # Extract nonce, ciphertext, and tag
    nonce = decoded_data[:12]
    ciphertext_with_tag = decoded_data[12:]
    # The last 16 bytes are typically the GCM tag for AES-GCM
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()
    try:
        # Decryption automatically verifies the tag
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext_bytes.decode('utf-8')
    except InvalidTag:
        print("Decryption failed: Authentication tag is invalid.")
        raise

# --- Airtable Interaction ---

def connect_airtable(api_key: str, base_id: str, table_name: str):
    """Connects to the specified Airtable table."""
    try:
        return Airtable(base_id, table_name, api_key)
    except Exception as e:
        print(f"Error connecting to Airtable: {e}")
        raise

def get_client_secrets(airtable_client: Airtable):
    """Fetches all client secrets from Airtable."""
    try:
        # Assuming 'client_id', 'encrypted_secret', and 'encrypted_refresh' are the relevant fields
        records = airtable_client.get_all()
        return records
    except Exception as e:
        print(f"Error fetching records from Airtable: {e}")
        raise

def update_airtable_record(airtable_client: Airtable, record_id: str, access_token: str, expiry_time: datetime):
    """Updates an Airtable record with new access token and expiry."""
    try:
        # Airtable expects the datetime in ISO 8601 format
        expiry_iso = expiry_time.isoformat()
        airtable_client.update(record_id, {
            'last_access_token': access_token,
            'access_token_expiry': expiry_iso
        })
        print(f"Successfully updated record {record_id} with new access token.")
    except Exception as e:
        print(f"Error updating Airtable record {record_id}: {e}")
        raise

# --- Token Refresh Logic ---

def get_new_access_token(client_id: str, client_secret: str, refresh_token: str):
    """
    Gets a new access token using the GoHighLevel OAuth 2.0 refresh token flow.

    Args:
        client_id: The client ID.
        client_secret: The decrypted client secret.
        refresh_token: The decrypted refresh token.

    Returns:
        A tuple containing (access_token: str, expiry_time: datetime).
        expiry_time is a timezone-aware datetime object.

    Raises:
        requests.exceptions.RequestException: If the HTTP request fails.
        ValueError: If the API response does not contain expected data.
    """
    token_url = "https://services.leadconnectorhq.com/oauth/token"

    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret,
    }

    print(f"Requesting new access token for client_id: {client_id}")

    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        token_data = response.json()

        access_token = token_data.get('access_token')
        expires_in = token_data.get('expires_in') # expires_in is usually in seconds
        # Optional: GoHighLevel might return a new refresh_token. You could store this if needed.
        # new_refresh_token = token_data.get('refresh_token')

        if not access_token or expires_in is None:
            raise ValueError("GoHighLevel API response missing access_token or expires_in.")

        # Calculate expiry time
        # Convert expires_in to seconds (it's usually an integer)
        expiry_seconds = int(expires_in)
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)

        print(f"Successfully obtained new token for client_id: {client_id}")
        return access_token, expiry_time

    except requests.exceptions.RequestException as e:
        print(f"HTTP request error during token refresh for {client_id}: {e}")
        raise # Re-raise the exception after logging
    except ValueError as e:
        print(f"Error parsing GoHighLevel API response for {client_id}: {e}")
        raise # Re-raise the exception after logging
    except Exception as e:
        print(f"An unexpected error occurred during token refresh for {client_id}: {e}")
        raise # Re-raise the exception after logging

def refresh_tokens_for_all_clients(config, encryption_key: bytes):
    """Fetches secrets, decrypts them, gets new tokens, and updates Airtable."""
    airtable_client = connect_airtable(config["airtable_api_key"], config["airtable_base_id"], config["airtable_table_name"])
    client_records = get_client_secrets(airtable_client)

    if not client_records:
        print("No client records found in Airtable.")
        return

    print(f"Found {len(client_records)} client record(s) to process.")

    for record in client_records:
        record_id = record['id']
        fields = record['fields']
        client_id = fields.get('client_id')
        encrypted_secret = fields.get('encrypted_secret')
        encrypted_refresh = fields.get('encrypted_refresh')

        if not all([client_id, encrypted_secret, encrypted_refresh]):
            print(f"Skipping record {record_id} due to missing client_id, encrypted_secret, or encrypted_refresh.")
            continue

        try:
            print(f"Processing client: {client_id}")
            # 3. Decrypt credentials
            client_secret = decrypt_data(encrypted_secret, encryption_key)
            refresh_token = decrypt_data(encrypted_refresh, encryption_key)
            # Avoid printing decrypted secrets
            # print(f"Decrypted secret for {client_id}: {client_secret}")
            # print(f"Decrypted refresh token for {client_id}: {refresh_token}")

            # 4. Call relevant API to get new access token
            # YOU MUST REPLACE THE FOLLOWING LINE WITH YOUR ACTUAL OAUTH CALL
            new_access_token, expiry_time = get_new_access_token(client_id, client_secret, refresh_token)

            # 5. Update Airtable with current access_token (unencrypted) and expiry
            update_airtable_record(airtable_client, record_id, new_access_token, expiry_time)

        except InvalidTag:
            print(f"Skipping client {client_id} due to decryption failure (Invalid Tag). Key might be incorrect or data corrupted.")
        except Exception as e:
            print(f"An error occurred while processing client {client_id}: {e}")
            # Continue processing other clients even if one fails

# --- Optional: Client Onboarding ---

def onboard_new_client(config, encryption_key: bytes, client_id: str, client_secret: str, refresh_token: str):
    """
    Encrypts client credentials and stores them in a new Airtable record.
    """
    airtable_client = connect_airtable(config["airtable_api_key"], config["airtable_base_id"], config["airtable_table_name"])

    try:
        print(f"Onboarding new client: {client_id}")
        # Encrypt sensitive credentials
        encrypted_secret = encrypt_data(client_secret, encryption_key)
        encrypted_refresh = encrypt_data(refresh_token, encryption_key)

        # Prepare data for Airtable
        new_record_data = {
            'client_id': client_id,
            'encrypted_secret': encrypted_secret,
            'encrypted_refresh': encrypted_refresh,
            # last_access_token and access_token_expiry will be populated on the first run
        }

        # Create new record in Airtable
        airtable_client.insert(new_record_data)
        print(f"Successfully added new client {client_id} to Airtable with encrypted credentials.")

    except Exception as e:
        print(f"Error onboarding new client {client_id}: {e}")
        raise


# --- Main Execution ---

if __name__ == "__main__":
    try:
        print("Starting token refresh process...")
        config = load_config()

        # 1. Load config and encryption key from environment variables
        encryption_key_bytes = config["encryption_key_bytes"]
        print("Encryption key loaded from environment variable.")

        # 2-5. Refresh tokens for all existing clients
        refresh_tokens_for_all_clients(config, encryption_key_bytes)

        print("Token refresh process completed.")

    except ValueError as ve:
        print(f"Configuration Error: {ve}")
        exit(1)
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        exit(1)