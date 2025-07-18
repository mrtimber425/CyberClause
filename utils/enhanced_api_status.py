import requests
import json
import os
from datetime import datetime
import threading
import time


class APIStatusManager:
    """Accurate API status checking and management"""

    def __init__(self, api_manager):
        self.api_manager = api_manager
        self.status_cache = {}
        self.last_check = {}
        self.check_interval = 300  # 5 minutes

    def get_api_status(self, service):
        """Get accurate API status for a service"""
        api_key = self.api_manager.get_api_key(service)

        if not api_key:
            return {
                'status': 'no_key',
                'message': 'No API key configured',
                'indicator': '⚪ Not Configured',
                'color': '#999999'
            }

        # Check if we have recent status
        if service in self.status_cache:
            last_check = self.last_check.get(service, 0)
            if time.time() - last_check < self.check_interval:
                return self.status_cache[service]

        # Perform actual API test
        return self.test_api_connection(service, api_key)

    def test_api_connection(self, service, api_key):
        """Test actual API connection"""
        try:
            if service == 'nvd':
                return self._test_nvd_api(api_key)
            elif service == 'virustotal':
                return self._test_virustotal_api(api_key)
            elif service == 'shodan':
                return self._test_shodan_api(api_key)
            else:
                return self._default_status('unknown_service')

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Connection error: {str(e)}',
                'indicator': '❌ Connection Error',
                'color': '#f44336'
            }

    def _test_nvd_api(self, api_key):
        """Test NVD API connection"""
        try:
            headers = {'apiKey': api_key} if api_key else {}

            # Test with a simple CVE query
            response = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                headers=headers,
                params={'resultsPerPage': 1},
                timeout=10
            )

            if response.status_code == 200:
                rate_limit = 'Unknown'
                if 'X-RateLimit-Remaining' in response.headers:
                    rate_limit = response.headers['X-RateLimit-Remaining']

                status = {
                    'status': 'connected',
                    'message': f'Connected successfully. Rate limit: {rate_limit}',
                    'indicator': '✅ Connected',
                    'color': '#4caf50',
                    'rate_limit': rate_limit
                }
            elif response.status_code == 401:
                status = {
                    'status': 'invalid_key',
                    'message': 'Invalid API key',
                    'indicator': '🔑 Invalid Key',
                    'color': '#f44336'
                }
            elif response.status_code == 429:
                status = {
                    'status': 'rate_limited',
                    'message': 'Rate limit exceeded',
                    'indicator': '⏱️ Rate Limited',
                    'color': '#ff9800'
                }
            else:
                status = {
                    'status': 'error',
                    'message': f'HTTP {response.status_code}',
                    'indicator': f'❌ Error {response.status_code}',
                    'color': '#f44336'
                }

            self.status_cache['nvd'] = status
            self.last_check['nvd'] = time.time()
            return status

        except requests.exceptions.Timeout:
            return {
                'status': 'timeout',
                'message': 'Connection timeout',
                'indicator': '⏱️ Timeout',
                'color': '#ff9800'
            }
        except requests.exceptions.ConnectionError:
            return {
                'status': 'no_connection',
                'message': 'No internet connection',
                'indicator': '🌐 No Internet',
                'color': '#f44336'
            }

    def _test_virustotal_api(self, api_key):
        """Test VirusTotal API connection"""
        try:
            headers = {'x-apikey': api_key}

            response = requests.get(
                'https://www.virustotal.com/api/v3/users/current',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                quota = data.get('data', {}).get('attributes', {}).get('quotas', {})

                return {
                    'status': 'connected',
                    'message': f'Connected. Daily quota: {quota.get("api_requests_daily", {}).get("allowed", "Unknown")}',
                    'indicator': '✅ Connected',
                    'color': '#4caf50',
                    'quota': quota
                }
            elif response.status_code == 401:
                return {
                    'status': 'invalid_key',
                    'message': 'Invalid API key',
                    'indicator': '🔑 Invalid Key',
                    'color': '#f44336'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'HTTP {response.status_code}',
                    'indicator': f'❌ Error {response.status_code}',
                    'color': '#f44336'
                }

        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'indicator': '❌ Error',
                'color': '#f44336'
            }

    def _test_shodan_api(self, api_key):
        """Test Shodan API connection"""
        try:
            response = requests.get(
                f'https://api.shodan.io/api-info?key={api_key}',
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'connected',
                    'message': f'Connected. Plan: {data.get("plan", "Unknown")}',
                    'indicator': '✅ Connected',
                    'color': '#4caf50',
                    'plan': data.get('plan'),
                    'query_credits': data.get('query_credits')
                }
            elif response.status_code == 401:
                return {
                    'status': 'invalid_key',
                    'message': 'Invalid API key',
                    'indicator': '🔑 Invalid Key',
                    'color': '#f44336'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'HTTP {response.status_code}',
                    'indicator': f'❌ Error {response.status_code}',
                    'color': '#f44336'
                }

        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'indicator': '❌ Error',
                'color': '#f44336'
            }

    def _default_status(self, status_type):
        """Default status responses"""
        status_map = {
            'unknown_service': {
                'status': 'unknown',
                'message': 'Unknown service',
                'indicator': '❓ Unknown',
                'color': '#999999'
            },
            'no_key': {
                'status': 'no_key',
                'message': 'No API key configured',
                'indicator': '⚪ Not Configured',
                'color': '#999999'
            }
        }
        return status_map.get(status_type, status_map['unknown_service'])