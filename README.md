# Encrypted Token Storage & Short-Lived Access Generation

This project provides a Python script to securely store API client secrets and refresh tokens in an encrypted format in Airtable. It periodically fetches these encrypted credentials, decrypts them using an encryption key stored in environment variables, generates short-lived access tokens from the respective API providers (specifically GoHighLevel in the current implementation), and updates Airtable with the new, unencrypted access tokens.

It also includes a separate script to securely add or update client credentials in Airtable.

## Requirements

*   Python 3.6+
*   Airtable account and API Key with Read/Write access to the `APISecrets` table
*   Required Python libraries (listed below)

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd token-refresh
    ```

2.  **Airtable Setup:**
    *   Create a Base and a Table named `APISecrets` (or configure the script to use a different name).
    *   Ensure the table has the following fields:
        *   `locationId` (String - or the field you use to identify records)
        *   `encrypted_secret` (String)
        *   `encrypted_refresh` (String)
        *   `last_access_token` (String)
        *   `access_token_expiry` (DateTime)
        *   `client_id` (String - this will be used in the OAuth process but is not encrypted at rest)

3.  **Environment Variables:**
    *   Copy the `.env.example` file to `.env`:
        ```bash
        cp .env.example .env
        ```
    *   Edit the `.env` file and fill in the required values:
        ```dotenv
        # A base64 encoded 32-byte key for AES-256 encryption.
        # You can generate one using Python: base64.b64encode(os.urandom(32)).decode('utf-8')
        ENCRYPTION_KEY=

        AIRTABLE_API_KEY=your_airtable_api_key
        AIRTABLE_BASE_ID=your_airtable_base_id
        AIRTABLE_TABLE_NAME=APISecrets
        ```
    *   **Generating an Encryption Key:** The `ENCRYPTION_KEY` must be a 32-byte key for AES-256. You can generate one using Python: `import os, base64; print(base64.b64encode(os.urandom(32)).decode('utf-8'))`. Copy the output and paste it into your `.env` file (and your deployment environment). **Keep this key secure!**

4.  **Install Dependencies:**
    *   Install the required Python packages. It is recommended to use a virtual environment.
    ```bash
    pip install airtable-python-wrapper cryptography python-dotenv requests
    ```
    *(Note: `python-dotenv` is useful for loading environment variables from the `.env` file when running locally. For deployment, you should configure environment variables directly in your hosting environment.)*

## Client Credential Management (`onboard_client.py`)

Use the `onboard_client.py` script to add or update client credentials in your Airtable table. This script will prompt you for the `locationId` of the record to update, the client's `client_secret`, and their `refresh_token`. It encrypts the sensitive credentials and updates the specified Airtable record.

To run the onboarding script:

```bash
python onboard_client.py
```

Follow the terminal prompts. Ensure the record with the specified `locationId` already exists in your Airtable table.

## Token Refresh Process (`token_manager.py`)

This script is designed to be run on a schedule (e.g., via cron). It reads encrypted credentials from Airtable, decrypts them using the `ENCRYPTION_KEY`, obtains new access tokens (currently implemented for GoHighLevel), and updates Airtable.

To run the token refresh script manually (for testing):n
```bash
python token_manager.py
```

## Deployment

This script can be deployed in various ways on a server with Python and the ability to set environment variables.

### Production Deployment (Hetzner)

The production instance of this script runs on the Hetzner server (`n8n-marketingtechpro`) under the `deploy` user.

*   **Code Location:** The project is located at `/home/deploy/token-refresh`.
*   **Scheduling:** The script is scheduled using a cron job owned by the `deploy` user.
*   **Checking the Cron Job:** To view or edit the cron job, use the following command while logged in as `root`:
    ```bash
    crontab -u deploy -l
    ```

### General Deployment Guidance

*   **Cron Job:** The simplest method is to set up a cron job to run the `token_manager.py` script periodically. Ensure that all the required environment variables (`ENCRYPTION_KEY`, `AIRTABLE_API_KEY`, `AIRTABLE_BASE_ID`, `AIRTABLE_TABLE_NAME`) are set in the environment where the cron job executes.

    Example crontab entry (adjust paths and times as needed):
    ```cron
    0 * * * * cd /path/to/your/token-refresh && source venv/bin/activate && ENCRYPTION_KEY="your_base64_key" AIRTABLE_API_KEY="your_key" AIRTABLE_BASE_ID="your_base_id" AIRTABLE_TABLE_NAME="APISecrets" python token_manager.py >> /var/log/token_refresh.log 2>&1
    ```
    *(Note: Directly embedding sensitive keys in the crontab file is not ideal for security. A more secure approach is to store these variables in a file with restricted permissions and source that file within your cron job command, or use a secrets management system if available on your server.)*

*   **Docker (Optional):** While potentially overkill for a single script, Docker provides excellent dependency isolation. You would create a Dockerfile that copies your code, installs dependencies, and sets environment variables during container creation or runtime. The container could then be scheduled using cron on the host.

When deploying, ensure your environment is configured with the necessary environment variables.

## Security Notes

*   **Encryption Key Management:** The encryption key is stored in environment variables. **It is critical to secure the environment where these variables are set and restrict access to it.** Avoid committing your `.env` file to version control.
*   **Airtable Storage:** Only encrypted secrets and unencrypted, short-lived access tokens are stored in Airtable.
*   **No Logging of Secrets:** The script is designed to avoid logging decrypted client secrets or refresh tokens.
*   **OAuth 2.0 Implementation:** The `get_new_access_token` function is currently implemented for GoHighLevel. If integrating with other APIs, you will need to modify this function with the correct OAuth 2.0 token refresh flow for each provider.
*   **Dependencies:** Regularly update your dependencies to patch security vulnerabilities.

## Future Enhancements

*   Implement robust error handling and logging.
*   Add support for multiple API providers with different OAuth flows.
*   Implement monitoring and alerting for token refresh failures or expiry issues.
