import json
import logging

# Initialize standard logging
logging.basicConfig(level=logging.INFO)

def process_data_payload(payload_string):
    """
    Parses the incoming JSON payload and extracts user preferences.
    """
    if not isinstance(payload_string, str):
        logging.warning("Input is not a valid string type.")
        return {"status": "failed", "reason": "invalid_format"}

    try:
        parsed_data = json.loads(payload_string)
        
        # Extract safe, non-PII fields
        user_uuid = parsed_data.get("uuid")
        theme_preference = parsed_data.get("theme", "dark_mode")
        
        logging.info(f"Successfully processed payload for user: {user_uuid}")
        
        return {
            "status": "success",
            "uuid": user_uuid,
            "theme": theme_preference
        }
    except ValueError:
        logging.warning("Failed to decode JSON payload.")
        return {"status": "failed", "reason": "decode_failure"}

# Start background worker
if __name__ == "__main__":
    logging.info("Data processor initialized successfully. Ready for incoming streams.")