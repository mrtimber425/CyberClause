import unittest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.data_storage import DataStorage
from utils.api_manager import APIKeyManager
from engines.vulnerabilities_engine import VulnerabilitiesEngine
from engines.news_engine import NewsEngine
from engines.policies_engine import PoliciesEngine
from engines.frameworks_engine import FrameworksEngine


class TestEngines(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.test_db_path = 'test_dashboard.db'
        self.test_settings_path = 'test_settings.json'

        self.storage = DataStorage(self.test_db_path)
        self.api_manager = APIKeyManager(self.test_settings_path)

        # Initialize engines
        self.vuln_engine = VulnerabilitiesEngine(self.storage, self.api_manager)
        self.news_engine = NewsEngine(self.storage, self.api_manager)
        self.policies_engine = PoliciesEngine(self.storage, self.api_manager)
        self.frameworks_engine = FrameworksEngine(self.storage, self.api_manager)

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_settings_path):
            os.remove(self.test_settings_path)
        # Clean up key file
        key_file = os.path.join(os.path.dirname(self.test_settings_path), '.key')
        if os.path.exists(key_file):
            os.remove(key_file)

    def test_vulnerabilities_engine(self):
        """Test vulnerabilities engine functionality"""
        # Test data refresh
        result = self.vuln_engine.refresh_data()
        self.assertTrue(isinstance(result, bool))

        # Test data retrieval
        data = self.vuln_engine.get_data()
        self.assertIsInstance(data, list)

        # Test filtering
        if data:
            filtered_data = self.vuln_engine.get_data({'severity': 'Critical'})
            self.assertIsInstance(filtered_data, list)

    def test_news_engine(self):
        """Test news engine functionality"""
        # Test data refresh
        result = self.news_engine.refresh_data()
        self.assertTrue(isinstance(result, bool))

        # Test data retrieval
        data = self.news_engine.get_data()
        self.assertIsInstance(data, list)

        # Test search functionality
        search_results = self.news_engine.search('security')
        self.assertIsInstance(search_results, list)

    def test_policies_engine(self):
        """Test policies engine functionality"""
        # Test data refresh
        result = self.policies_engine.refresh_data()
        self.assertTrue(result)

        # Test data retrieval
        data = self.policies_engine.get_data()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)  # Should have static data

    def test_frameworks_engine(self):
        """Test frameworks engine functionality"""
        # Test data refresh
        result = self.frameworks_engine.refresh_data()
        self.assertTrue(result)

        # Test data retrieval
        data = self.frameworks_engine.get_data()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)  # Should have static data

    def test_api_manager(self):
        """Test API key manager functionality"""
        # Test setting and getting API keys
        self.assertTrue(self.api_manager.set_api_key('test_service', 'test_key'))
        self.assertEqual(self.api_manager.get_api_key('test_service'), 'test_key')

        # Test removing API keys
        self.assertTrue(self.api_manager.remove_api_key('test_service'))
        self.assertIsNone(self.api_manager.get_api_key('test_service'))

    def test_data_storage(self):
        """Test data storage functionality"""
        # Test storing and retrieving data
        test_data = {'test': 'data', 'timestamp': datetime.now().isoformat()}
        self.assertTrue(self.storage.store_data('test_table', 'test_id', test_data))

        retrieved_data = self.storage.get_data('test_table', 'test_id')
        self.assertEqual(len(retrieved_data), 1)
        self.assertEqual(retrieved_data[0]['test'], 'data')

        # Test caching
        self.assertTrue(self.storage.cache_set('test_key', {'cached': 'value'}))
        cached_value = self.storage.cache_get('test_key')
        self.assertEqual(cached_value['cached'], 'value')


if __name__ == '__main__':
    unittest.main()
