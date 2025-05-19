import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from airtable import Airtable
from token_manager import encrypt_data, load_config

# Load environment variables
load_dotenv()

def exchange_authorization_code(client_id: str, client_secret: str, auth_code: str, redirect_uri: str) -> dict:
    """Exchange authorization code for access token and refresh token"""
    token_url = "https://services.leadconnectorhq.com/oauth/token"

    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': redirect_uri
    }

    response = requests.post(token_url, data=payload)
    response.raise_for_status()
    return response.json()

def onboard_new_client():
    """Handles the complete onboarding flow for a new client"""
    try:
        print("=== GoHighLevel OAuth Onboarding ===")
        location_id = input("Enter Location ID: ").strip()
        client_id = input("Enter Client ID: ").strip()
        client_secret = input("Enter Client Secret: ").strip()
        auth_code = input("Enter Authorization Code: ").strip()
        redirect_uri = input("Enter Redirect URI used: ").strip()

        # Exchange authorization code for tokens
        token_data = exchange_authorization_code(client_id, client_secret, auth_code, redirect_uri)

        # Validate response
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in')

        if not all([access_token, refresh_token, expires_in]):
            raise ValueError("API response missing required tokens")

        # Load encryption configuration
        config = load_config()
        encryption_key = config['encryption_key_bytes']

        # Encrypt sensitive credentials
        encrypted_secret = encrypt_data(client_secret, encryption_key)
        encrypted_refresh = encrypt_data(refresh_token, encryption_key)

        # Calculate expiry time
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

        # Connect to Airtable
        airtable = Airtable(
            base_id=config["airtable_base_id"],
            table_name=config["airtable_table_name"],
            api_key=config["airtable_api_key"]
        )

        # Check for existing record with locationId
        existing_records = airtable.search("locationId", location_id)

        update_data = {
            'client_id': client_id,
            'encrypted_secret': encrypted_secret,
            'encrypted_refresh': encrypted_refresh,
            'last_access_token': access_token,
            'access_token_expiry': expiry_time.isoformat()
        }

        if existing_records:
            # Update existing record
            record_id = existing_records[0]['id']
            airtable.update(record_id, update_data)
            print(f"✅ Updated existing record for locationId: {location_id}")
        else:
            # Create new record with locationId
            airtable.insert({'locationId': location_id, **update_data})
            print(f"✅ Created new record for locationId: {location_id}")

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"🚨 Onboarding failed: {str(e)}")

if __name__ == "__main__":
    onboard_new_client()