import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_clients.nvd_client import NVDClient
from api_clients.rss_client import RSSClient
from config import Config


class TestAPIClients(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.nvd_client = NVDClient()
        self.rss_client = RSSClient({'Test Feed': 'https://feeds.feedburner.com/oreilly/radar'})

    def test_nvd_client_connection(self):
        """Test NVD client connection"""
        # Test connection without making actual API calls
        self.assertIsNotNone(self.nvd_client.base_url)
        self.assertIsNotNone(self.nvd_client.session)

    def test_rss_client_parsing(self):
        """Test RSS client parsing capabilities"""
        # Test categorization function
        category = self.rss_client._categorize_article(
            "Critical vulnerability found in Apache",
            "A serious security flaw has been discovered"
        )
        self.assertIn(category, ['Vulnerabilities', 'General Security'])

    def test_nvd_cve_parsing(self):
        """Test CVE data parsing"""
        # Mock CVE data structure
        mock_vulnerability = {
            'cve': {
                'id': 'CVE-2024-0001',
                'descriptions': [{'lang': 'en', 'value': 'Test vulnerability description'}],
                'published': '2024-01-01T00:00:00.000Z',
                'metrics': {
                    'cvssMetricV31': [{
                        'cvssData': {
                            'baseScore': 9.8,
                            'baseSeverity': 'CRITICAL'
                        }
                    }]
                },
                'configurations': []
            }
        }

        parsed_cves = self.nvd_client._parse_cves([mock_vulnerability])
        self.assertEqual(len(parsed_cves), 1)
        self.assertEqual(parsed_cves[0]['cve_id'], 'CVE-2024-0001')
        self.assertEqual(parsed_cves[0]['cvss_score'], 9.8)


if __name__ == '__main__':
    unittest.main()