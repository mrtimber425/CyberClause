import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import threading


class DataStorage:
    """Simplified data storage for live search mode - no local CVE database"""

    def __init__(self, db_path: str = None):
        # Keep minimal storage for settings and cache only
        self.cache_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'cache')
        self.settings_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        self.lock = threading.Lock()
        self._ensure_directories()

        # In-memory cache for API results
        self.memory_cache = {}
        self.cache_timestamps = {}
        self.max_cache_size = 100
        self.default_cache_timeout = 300  # 5 minutes

    def _ensure_directories(self):
        """Ensure cache and settings directories exist"""
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.settings_dir, exist_ok=True)

    def cache_set(self, key: str, value: Any, expires_in: timedelta = None) -> bool:
        """Set cache value in memory"""
        if expires_in is None:
            expires_in = timedelta(seconds=self.default_cache_timeout)

        expires_at = datetime.now() + expires_in

        with self.lock:
            # Clean old entries if cache is full
            if len(self.memory_cache) >= self.max_cache_size:
                self._cleanup_expired_cache()

                # If still full, remove oldest entries
                if len(self.memory_cache) >= self.max_cache_size:
                    oldest_keys = sorted(self.cache_timestamps.keys(),
                                         key=lambda k: self.cache_timestamps[k])[:10]
                    for old_key in oldest_keys:
                        self.memory_cache.pop(old_key, None)
                        self.cache_timestamps.pop(old_key, None)

            self.memory_cache[key] = value
            self.cache_timestamps[key] = expires_at

        return True

    def cache_get(self, key: str) -> Optional[Any]:
        """Get cache value from memory"""
        with self.lock:
            if key not in self.memory_cache:
                return None

            # Check if expired
            if key in self.cache_timestamps:
                if datetime.now() > self.cache_timestamps[key]:
                    # Expired, remove it
                    self.memory_cache.pop(key, None)
                    self.cache_timestamps.pop(key, None)
                    return None

            return self.memory_cache.get(key)

    def _cleanup_expired_cache(self):
        """Clean up expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, expires_at in self.cache_timestamps.items()
            if now > expires_at
        ]

        for key in expired_keys:
            self.memory_cache.pop(key, None)
            self.cache_timestamps.pop(key, None)

    def clear_cache(self):
        """Clear all cached data"""
        with self.lock:
            self.memory_cache.clear()
            self.cache_timestamps.clear()

    def get_cache_statistics(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            now = datetime.now()
            active_entries = sum(
                1 for expires_at in self.cache_timestamps.values()
                if now <= expires_at
            )

            return {
                'total_entries': len(self.memory_cache),
                'active_entries': active_entries,
                'expired_entries': len(self.memory_cache) - active_entries,
                'cache_size_limit': self.max_cache_size,
                'cache_usage_percent': (len(self.memory_cache) / self.max_cache_size) * 100
            }

    def save_search_history(self, search_query: str, results_count: int):
        """Save search history to file"""
        try:
            history_file = os.path.join(self.settings_dir, 'search_history.json')

            # Load existing history
            history = []
            if os.path.exists(history_file):
                try:
                    with open(history_file, 'r') as f:
                        history = json.load(f)
                except:
                    history = []

            # Add new search
            search_entry = {
                'query': search_query,
                'results_count': results_count,
                'timestamp': datetime.now().isoformat(),
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            history.append(search_entry)

            # Keep only last 100 searches
            history = history[-100:]

            # Save updated history
            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2)

        except Exception as e:
            print(f"Error saving search history: {e}")

    def get_search_history(self, limit: int = 20) -> List[Dict]:
        """Get recent search history"""
        try:
            history_file = os.path.join(self.settings_dir, 'search_history.json')

            if not os.path.exists(history_file):
                return []

            with open(history_file, 'r') as f:
                history = json.load(f)

            # Return most recent searches
            return history[-limit:] if history else []

        except Exception as e:
            print(f"Error loading search history: {e}")
            return []

    def save_api_statistics(self, api_name: str, stats: Dict):
        """Save API usage statistics"""
        try:
            stats_file = os.path.join(self.settings_dir, f'{api_name}_stats.json')

            # Load existing stats
            all_stats = {}
            if os.path.exists(stats_file):
                try:
                    with open(stats_file, 'r') as f:
                        all_stats = json.load(f)
                except:
                    all_stats = {}

            # Add current stats
            date_key = datetime.now().strftime('%Y-%m-%d')
            if date_key not in all_stats:
                all_stats[date_key] = []

            stats['timestamp'] = datetime.now().isoformat()
            all_stats[date_key].append(stats)

            # Keep only last 30 days
            cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            all_stats = {
                date: data for date, data in all_stats.items()
                if date >= cutoff_date
            }

            # Save updated stats
            with open(stats_file, 'w') as f:
                json.dump(all_stats, f, indent=2)

        except Exception as e:
            print(f"Error saving API statistics: {e}")

    def get_api_statistics(self, api_name: str) -> Dict:
        """Get API usage statistics"""
        try:
            stats_file = os.path.join(self.settings_dir, f'{api_name}_stats.json')

            if not os.path.exists(stats_file):
                return {}

            with open(stats_file, 'r') as f:
                all_stats = json.load(f)

            # Calculate summary statistics
            total_requests = 0
            total_results = 0
            recent_requests = 0

            today = datetime.now().strftime('%Y-%m-%d')

            for date, day_stats in all_stats.items():
                for stat in day_stats:
                    total_requests += stat.get('requests', 0)
                    total_results += stat.get('results', 0)

                    if date == today:
                        recent_requests += stat.get('requests', 0)

            return {
                'total_requests': total_requests,
                'total_results': total_results,
                'today_requests': recent_requests,
                'days_tracked': len(all_stats),
                'raw_stats': all_stats
            }

        except Exception as e:
            print(f"Error loading API statistics: {e}")
            return {}

    # Legacy compatibility methods (simplified/stubbed)
    def store_data(self, table: str, data_id: str, data: Dict) -> bool:
        """Legacy compatibility - store in cache instead"""
        cache_key = f"{table}_{data_id}"
        return self.cache_set(cache_key, data, timedelta(hours=1))

    def get_data(self, table: str, data_id: str = None, filters: Dict = None) -> List[Dict]:
        """Legacy compatibility - return empty list (no local storage)"""
        return []

    def get_table_statistics(self, table: str) -> Dict:
        """Legacy compatibility - return empty stats"""
        return {
            'total_records': 0,
            'message': 'Live search mode - no local storage'
        }

    def import_cve_csv_historical(self, csv_path: str) -> bool:
        """Legacy compatibility - not supported in live mode"""
        print("CSV import not supported in live search mode")
        return False

    def get_import_status(self) -> List[Dict]:
        """Legacy compatibility - return empty status"""
        return []

    def export_cache_summary(self) -> Dict:
        """Export cache summary for debugging"""
        stats = self.get_cache_statistics()
        search_history = self.get_search_history(10)

        return {
            'cache_statistics': stats,
            'recent_searches': search_history,
            'mode': 'live_search',
            'timestamp': datetime.now().isoformat()
        }

    def cleanup_old_files(self):
        """Clean up old cache files"""
        try:
            # Clean up old cache files (older than 1 week)
            cutoff_time = datetime.now() - timedelta(days=7)

            for filename in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, filename)
                if os.path.isfile(file_path):
                    file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                    if file_time < cutoff_time:
                        try:
                            os.remove(file_path)
                        except:
                            pass

        except Exception as e:
            print(f"Error cleaning up old files: {e}")

    def get_storage_info(self) -> Dict:
        """Get information about storage mode and usage"""
        return {
            'mode': 'live_search',
            'description': 'Live CVE search using NVD API - no local database',
            'cache_statistics': self.get_cache_statistics(),
            'cache_directory': self.cache_dir,
            'settings_directory': self.settings_dir,
            'features': [
                'In-memory result caching',
                'Search history tracking',
                'API usage statistics',
                'No local CVE database required'
            ],
            'benefits': [
                'Always up-to-date CVE information',
                'No large local files',
                'Faster startup time',
                'Reduced disk usage'
            ]
        }