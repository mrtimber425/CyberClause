import requests
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json


class NVDClient:
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.session = requests.Session()

        # Set headers
        self.headers = {
            'User-Agent': 'CyberClause-Dashboard/3.1 (cybersecurity-research)',
            'Accept': 'application/json'
        }

        if self.api_key:
            self.headers['apiKey'] = self.api_key
            # With API key: 50 requests per 30 seconds
            self.rate_limit_delay = 0.6  # seconds between requests
        else:
            # Without API key: 5 requests per 30 seconds
            self.rate_limit_delay = 6.0  # seconds between requests

        self.session.headers.update(self.headers)
        self.last_request_time = 0

    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _make_request(self, params: Dict) -> Optional[Dict]:
        """Make rate-limited request to NVD API"""
        self._rate_limit()

        try:
            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                print("Rate limit exceeded, waiting...")
                time.sleep(60)  # Wait 1 minute
                return self._make_request(params)  # Retry
            else:
                print(f"NVD API error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def search_cves(self,
                    cve_id: str = None,
                    keyword: str = None,
                    cvss_severity: str = None,
                    start_date: str = None,
                    end_date: str = None,
                    max_results: int = 100) -> List[Dict]:
        """Enhanced CVE search with multiple parameters"""

        params = {'resultsPerPage': min(max_results, 2000)}

        if cve_id:
            params['cveId'] = cve_id

        if keyword:
            params['keywordSearch'] = keyword

        if cvss_severity:
            # Map severity to CVSS score ranges
            severity_ranges = {
                'LOW': '0.1-3.9',
                'MEDIUM': '4.0-6.9',
                'HIGH': '7.0-8.9',
                'CRITICAL': '9.0-10.0'
            }
            if cvss_severity.upper() in severity_ranges:
                params['cvssV3Severity'] = cvss_severity.upper()

        if start_date:
            params['pubStartDate'] = start_date

        if end_date:
            params['pubEndDate'] = end_date

        data = self._make_request(params)

        if not data or 'vulnerabilities' not in data:
            return []

        return self._parse_cves(data['vulnerabilities'])

    def get_recent_cves(self, days: int = 7, severity: str = None) -> List[Dict]:
        """Get CVEs from the last N days with optional severity filter"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 100
        }

        if severity:
            params['cvssV3Severity'] = severity.upper()

        data = self._make_request(params)
        if not data or 'vulnerabilities' not in data:
            return []

        return self._parse_cves(data['vulnerabilities'])

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Get specific CVE by ID"""
        params = {'cveId': cve_id}
        data = self._make_request(params)

        if not data or 'vulnerabilities' not in data:
            return None

        vulnerabilities = data['vulnerabilities']
        if not vulnerabilities:
            return None

        parsed_cves = self._parse_cves(vulnerabilities)
        return parsed_cves[0] if parsed_cves else None

    def search_by_product(self, product_name: str, max_results: int = 50) -> List[Dict]:
        """Search CVEs affecting a specific product"""
        params = {
            'keywordSearch': product_name,
            'resultsPerPage': min(max_results, 500)
        }

        data = self._make_request(params)
        if not data or 'vulnerabilities' not in data:
            return []

        return self._parse_cves(data['vulnerabilities'])

    def search_critical_recent(self, days: int = 30) -> List[Dict]:
        """Get critical/high severity CVEs from recent days"""
        results = []

        # Get critical CVEs
        critical_cves = self.get_recent_cves(days=days, severity='CRITICAL')
        results.extend(critical_cves)

        # Get high severity CVEs (limit to avoid too many results)
        high_cves = self.get_recent_cves(days=days, severity='HIGH')
        results.extend(high_cves[:20])  # Limit high severity

        # Sort by CVSS score
        results.sort(key=lambda x: float(x.get('cvss_score', 0) or 0), reverse=True)

        return results[:50]  # Return top 50

    def _parse_cves(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse CVE data from NVD API response"""
        parsed_cves = []

        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')

                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Get CVSS score and severity
                cvss_score = 0.0
                severity = 'Unknown'
                cvss_vector = ''

                metrics = cve_data.get('metrics', {})

                # Try CVSS v3.1 first, then v3.0, then v2.0
                for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if cvss_version in metrics and metrics[cvss_version]:
                        cvss_data = metrics[cvss_version][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        cvss_vector = cvss_data.get('vectorString', '')

                        if cvss_version.startswith('cvssMetricV3'):
                            severity = cvss_data.get('baseSeverity', 'Unknown')
                        else:
                            # Convert CVSS v2 score to severity
                            if cvss_score >= 9.0:
                                severity = 'CRITICAL'
                            elif cvss_score >= 7.0:
                                severity = 'HIGH'
                            elif cvss_score >= 4.0:
                                severity = 'MEDIUM'
                            else:
                                severity = 'LOW'
                        break

                # Get affected products
                affected_products = []
                configurations = cve_data.get('configurations', [])

                for config in configurations:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for match in cpe_matches:
                            cpe_name = match.get('criteria', '')
                            if cpe_name:
                                product_name = self._parse_cpe_name(cpe_name)
                                if product_name and product_name not in affected_products:
                                    affected_products.append(product_name)

                # Get references
                references = []
                ref_data = cve_data.get('references', [])
                for ref in ref_data:
                    references.append({
                        'url': ref.get('url', ''),
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    })

                # Get weaknesses (CWE)
                weaknesses = []
                weakness_data = cve_data.get('weaknesses', [])
                for weakness in weakness_data:
                    descriptions = weakness.get('description', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            weaknesses.append(desc.get('value', ''))

                # Parse dates
                published = cve_data.get('published', '')
                modified = cve_data.get('lastModified', '')

                parsed_cve = {
                    'cve_id': cve_id,
                    'title': f"{cve_id} - {severity} Severity Vulnerability",
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'severity': severity,
                    'published': published,
                    'modified': modified,
                    'affected_products': affected_products[:10],  # Limit to prevent huge lists
                    'references': references[:5],  # Limit references
                    'weaknesses': weaknesses[:3],  # Limit weaknesses
                    'source': 'NVD API (Live)',
                    'source_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                    'category': 'Vulnerability',
                    'is_recent': self._is_recent(published),
                    'threat_level': self._assess_threat_level(cvss_score, severity)
                }

                parsed_cves.append(parsed_cve)

            except Exception as e:
                print(f"Error parsing CVE {cve_data.get('id', 'Unknown')}: {e}")
                continue

        return parsed_cves

    def _parse_cpe_name(self, cpe_name: str) -> str:
        """Parse CPE name to get readable product name"""
        try:
            # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_name.split(':')

            if len(parts) >= 5:
                vendor = parts[3].replace('_', ' ').title()
                product = parts[4].replace('_', ' ').title()

                if vendor.lower() != product.lower():
                    return f"{vendor} {product}"
                else:
                    return product

            return cpe_name

        except Exception:
            return cpe_name

    def _is_recent(self, published_date: str) -> bool:
        """Check if CVE is from last 30 days"""
        try:
            if not published_date:
                return False

            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            cutoff_date = datetime.now() - timedelta(days=30)

            return pub_date.replace(tzinfo=None) > cutoff_date
        except:
            return False

    def _assess_threat_level(self, cvss_score: float, severity: str) -> str:
        """Assess threat level based on CVSS and other factors"""
        if severity == 'CRITICAL' or cvss_score >= 9.0:
            return 'Critical'
        elif severity == 'HIGH' or cvss_score >= 7.0:
            return 'High'
        elif severity == 'MEDIUM' or cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    def get_statistics(self) -> Dict:
        """Get API connection statistics"""
        return {
            'api_status': 'Connected' if self.api_key else 'Limited (No API Key)',
            'rate_limit': f"{1 / self.rate_limit_delay:.1f} requests per second",
            'base_url': self.base_url,
            'has_api_key': bool(self.api_key)
        }