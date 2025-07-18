import requests
from typing import Dict, List, Optional
import time
from datetime import datetime


class BaseAPIClient:
    def __init__(self, base_url: str, api_key: str = None, rate_limit: float = 1.0):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.rate_limit = rate_limit  # Seconds between requests
        self.last_request_time = 0
        self.session = requests.Session()

        # Set common headers
        self.session.headers.update({
            'User-Agent': 'CyberSec-Dashboard/1.0'
        })

        if api_key:
            self._set_auth_headers()

    def _set_auth_headers(self):
        """Set authentication headers - override in subclasses"""
        pass

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: Dict = None, timeout: int = 30) -> Optional[Dict]:
        """Make a rate-limited API request"""
        self._rate_limit_wait()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API request failed for {url}: {e}")
            return None
        except ValueError as e:
            print(f"Failed to parse JSON response from {url}: {e}")
            return None

    def test_connection(self) -> bool:
        """Test if the API is accessible"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            return response.status_code < 500
        except:
            return False