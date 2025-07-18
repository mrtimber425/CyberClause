from .base_engine import BaseEngine
from api_clients.nvd_client import NVDClient
from typing import List, Dict
from datetime import datetime, timedelta
import threading
import time


class VulnerabilitiesEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(hours=1)
        self.nvd_client = None
        self._init_clients()
        self.recent_cache = {}
        self.cache_timeout = 300  # 5 minutes cache

    def _init_clients(self):
        """Initialize API clients"""
        nvd_api_key = self.api_manager.get_api_key('nvd')
        self.nvd_client = NVDClient(nvd_api_key)

    def search_cves(self,
                    query: str = None,
                    cve_id: str = None,
                    severity: str = None,
                    days_back: int = None,
                    max_results: int = 50) -> List[Dict]:
        """Live CVE search using NVD API"""
        try:
            # Prepare search parameters
            search_params = {}

            if cve_id:
                # Direct CVE ID search
                result = self.nvd_client.get_cve_by_id(cve_id)
                return [result] if result else []

            if query:
                search_params['keyword'] = query

            if severity:
                search_params['cvss_severity'] = severity

            if days_back:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days_back)
                search_params['start_date'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
                search_params['end_date'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')

            search_params['max_results'] = max_results

            # Perform search
            results = self.nvd_client.search_cves(**search_params)

            # Cache results for quick access
            cache_key = f"{query or ''}_{cve_id or ''}_{severity or ''}_{days_back or ''}"
            self.recent_cache[cache_key] = {
                'results': results,
                'timestamp': time.time()
            }

            return results

        except Exception as e:
            print(f"Error searching CVEs: {e}")
            return []

    def get_recent_critical(self, days: int = 7) -> List[Dict]:
        """Get recent critical/high CVEs with caching"""
        cache_key = f"critical_{days}"

        # Check cache
        if cache_key in self.recent_cache:
            cached = self.recent_cache[cache_key]
            if time.time() - cached['timestamp'] < self.cache_timeout:
                return cached['results']

        try:
            results = self.nvd_client.search_critical_recent(days=days)

            # Cache results
            self.recent_cache[cache_key] = {
                'results': results,
                'timestamp': time.time()
            }

            return results

        except Exception as e:
            print(f"Error getting critical CVEs: {e}")
            return []

    def search_by_product(self, product_name: str) -> List[Dict]:
        """Search CVEs affecting specific product"""
        try:
            return self.nvd_client.search_by_product(product_name)
        except Exception as e:
            print(f"Error searching product CVEs: {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Dict:
        """Get detailed information for specific CVE"""
        try:
            # Check cache first
            cache_key = f"details_{cve_id}"
            if cache_key in self.recent_cache:
                cached = self.recent_cache[cache_key]
                if time.time() - cached['timestamp'] < self.cache_timeout:
                    return cached['results']

            # Fetch from API
            result = self.nvd_client.get_cve_by_id(cve_id)

            if result:
                # Enhance with additional details
                enhanced_result = self._enhance_cve_details(result)

                # Cache enhanced result
                self.recent_cache[cache_key] = {
                    'results': enhanced_result,
                    'timestamp': time.time()
                }

                return enhanced_result

            return {}

        except Exception as e:
            print(f"Error getting CVE details: {e}")
            return {}

    def _enhance_cve_details(self, cve_data: Dict) -> Dict:
        """Enhance CVE data with additional analysis"""
        enhanced = cve_data.copy()

        # Add impact assessment
        cvss_score = float(enhanced.get('cvss_score', 0) or 0)
        severity = enhanced.get('severity', 'Unknown')

        if cvss_score >= 9.0 or severity == 'CRITICAL':
            enhanced['impact_level'] = 'Critical - Immediate action required'
            enhanced['recommended_action'] = 'Apply patches immediately, consider taking systems offline'
            enhanced['priority'] = 'P1 - Critical'
        elif cvss_score >= 7.0 or severity == 'HIGH':
            enhanced['impact_level'] = 'High - Urgent attention needed'
            enhanced['recommended_action'] = 'Apply patches within 72 hours'
            enhanced['priority'] = 'P2 - High'
        elif cvss_score >= 4.0 or severity == 'MEDIUM':
            enhanced['impact_level'] = 'Medium - Monitor and patch'
            enhanced['recommended_action'] = 'Apply patches during next maintenance window'
            enhanced['priority'] = 'P3 - Medium'
        else:
            enhanced['impact_level'] = 'Low - Normal priority'
            enhanced['recommended_action'] = 'Include in regular patching cycle'
            enhanced['priority'] = 'P4 - Low'

        # Add timeline information
        enhanced['days_since_published'] = self._days_since_published(enhanced.get('published', ''))

        # Add exploitability assessment
        enhanced['exploitability'] = self._assess_exploitability(enhanced)

        # Add reference links
        enhanced['reference_links'] = self._generate_reference_links(enhanced.get('cve_id', ''))

        return enhanced

    def _days_since_published(self, published_date: str) -> int:
        """Calculate days since CVE was published"""
        try:
            if not published_date:
                return 0

            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            days_diff = (datetime.now() - pub_date.replace(tzinfo=None)).days
            return max(0, days_diff)
        except:
            return 0

    def _assess_exploitability(self, cve_data: Dict) -> str:
        """Assess exploitability based on available information"""
        cvss_score = float(cve_data.get('cvss_score', 0) or 0)
        days_old = self._days_since_published(cve_data.get('published', ''))
        references = cve_data.get('references', [])

        # Check for exploit references
        exploit_indicators = ['exploit', 'poc', 'metasploit', 'exploit-db']
        has_exploit_refs = any(
            any(indicator in ref.get('url', '').lower() for indicator in exploit_indicators)
            for ref in references
        )

        if has_exploit_refs:
            return 'High - Public exploits available'
        elif cvss_score >= 7.0 and days_old > 30:
            return 'Medium - High severity, time for exploit development'
        elif cvss_score >= 7.0:
            return 'Medium - High severity, monitor for exploits'
        else:
            return 'Low - Limited exploit potential'

    def _generate_reference_links(self, cve_id: str) -> List[Dict]:
        """Generate reference links for CVE"""
        if not cve_id:
            return []

        links = [
            {
                'name': 'NVD Official',
                'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'type': 'official'
            },
            {
                'name': 'MITRE CVE',
                'url': f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}',
                'type': 'official'
            },
            {
                'name': 'CVE Details',
                'url': f'https://www.cvedetails.com/cve/{cve_id}/',
                'type': 'analysis'
            },
            {
                'name': 'Exploit-DB Search',
                'url': f'https://www.exploit-db.com/search?cve={cve_id}',
                'type': 'exploits'
            }
        ]
        return links

    def get_trending_cves(self) -> List[Dict]:
        """Get trending/popular CVEs (recent high-severity)"""
        cache_key = "trending"

        # Check cache
        if cache_key in self.recent_cache:
            cached = self.recent_cache[cache_key]
            if time.time() - cached['timestamp'] < self.cache_timeout:
                return cached['results']

        try:
            # Get recent critical and high severity CVEs
            results = self.nvd_client.search_critical_recent(days=14)

            # Sort by recency and severity
            results.sort(key=lambda x: (
                x.get('severity') == 'CRITICAL',
                float(x.get('cvss_score', 0) or 0),
                x.get('is_recent', False)
            ), reverse=True)

            # Cache results
            self.recent_cache[cache_key] = {
                'results': results[:10],  # Top 10 trending
                'timestamp': time.time()
            }

            return results[:10]

        except Exception as e:
            print(f"Error getting trending CVEs: {e}")
            return []

    def get_statistics(self) -> Dict:
        """Get search statistics and API status"""
        try:
            api_stats = self.nvd_client.get_statistics()

            stats = {
                'api_status': api_stats.get('api_status', 'Unknown'),
                'has_api_key': api_stats.get('has_api_key', False),
                'rate_limit': api_stats.get('rate_limit', 'Unknown'),
                'cache_entries': len(self.recent_cache),
                'data_source': 'NVD API (Live Search)',
                'search_mode': 'Real-time API',
                'last_search': self.last_refresh.isoformat() if self.last_refresh else None
            }

            return stats

        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                'api_status': 'Error',
                'data_source': 'NVD API (Live Search)',
                'search_mode': 'Real-time API',
                'error': str(e)
            }

    def clear_cache(self):
        """Clear search cache"""
        self.recent_cache.clear()

    def refresh_data(self) -> bool:
        """Refresh cached data - for compatibility"""
        try:
            # Clear old cache
            self.clear_cache()

            # Pre-populate with recent critical CVEs
            self.get_recent_critical(days=7)
            self.get_trending_cves()

            self.last_refresh = datetime.now()
            return True

        except Exception as e:
            print(f"Error refreshing vulnerability data: {e}")
            return False

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get data - return recent critical CVEs by default"""
        # For compatibility with existing code
        if not filters:
            return self.get_recent_critical(days=7)

        # Parse filters for search
        search_query = filters.get('search', '')
        severity = filters.get('severity', '')
        days_back = filters.get('days_back', 7)

        return self.search_cves(
            query=search_query,
            severity=severity,
            days_back=days_back
        )

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search interface for compatibility"""
        severity = filters.get('severity') if filters else None
        days_back = filters.get('days_back', 30) if filters else 30

        return self.search_cves(
            query=query,
            severity=severity,
            days_back=days_back
        )