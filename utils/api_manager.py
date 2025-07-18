import json
import os
from typing import Dict, Optional
from cryptography.fernet import Fernet
import base64


class APIKeyManager:
    def __init__(self, settings_file: str):
        self.settings_file = settings_file
        self.cipher = self._get_or_create_cipher()
        self._ensure_settings_file()

    def _get_or_create_cipher(self) -> Fernet:
        """Get or create encryption key for API keys"""
        key_file = os.path.join(os.path.dirname(self.settings_file), '.key')

        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)

        return Fernet(key)

    def _ensure_settings_file(self):
        """Ensure settings file exists with default structure"""
        if not os.path.exists(self.settings_file):
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            default_settings = {
                'api_keys': {},
                'refresh_intervals': {
                    'vulnerabilities': 60,
                    'news': 30,
                    'policies': 240,
                    'frameworks': 480
                },
                'auto_refresh': True,
                'last_updated': None
            }
            self._save_settings(default_settings)

    def _load_settings(self) -> Dict:
        """Load settings from file"""
        try:
            with open(self.settings_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_settings(self, settings: Dict):
        """Save settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def set_api_key(self, service: str, api_key: str) -> bool:
        """Store an encrypted API key"""
        try:
            settings = self._load_settings()

            if 'api_keys' not in settings:
                settings['api_keys'] = {}

            # Encrypt the API key
            encrypted_key = self.cipher.encrypt(api_key.encode()).decode()
            settings['api_keys'][service] = encrypted_key

            self._save_settings(settings)
            return True
        except Exception as e:
            print(f"Error setting API key for {service}: {e}")
            return False

    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve and decrypt an API key"""
        try:
            settings = self._load_settings()
            encrypted_key = settings.get('api_keys', {}).get(service)

            if encrypted_key:
                return self.cipher.decrypt(encrypted_key.encode()).decode()
            return None
        except Exception as e:
            print(f"Error getting API key for {service}: {e}")
            return None

    def remove_api_key(self, service: str) -> bool:
        """Remove an API key"""
        try:
            settings = self._load_settings()
            if service in settings.get('api_keys', {}):
                del settings['api_keys'][service]
                self._save_settings(settings)
                return True
            return False
        except Exception as e:
            print(f"Error removing API key for {service}: {e}")
            return False

    def get_all_services(self) -> list:
        """Get list of services with stored API keys"""
        settings = self._load_settings()
        return list(settings.get('api_keys', {}).keys())

    def validate_api_key(self, service: str, api_key: str = None) -> bool:
        """Validate an API key by making a test request"""
        if api_key is None:
            api_key = self.get_api_key(service)

        if not api_key:
            return False

        # Add validation logic for specific services
        # This is a placeholder - implement actual validation for each service
        return len(api_key) > 10  # Basic length check

    def get_settings(self) -> Dict:
        """Get all settings"""
        return self._load_settings()

    def update_settings(self, new_settings: Dict) -> bool:
        """Update settings"""
        try:
            current_settings = self._load_settings()
            current_settings.update(new_settings)
            self._save_settings(current_settings)
            return True
        except Exception as e:
            print(f"Error updating settings: {e}")
            return False