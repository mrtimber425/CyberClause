import re
import urllib.parse
from typing import List, Dict, Tuple
import difflib


class MLLinkValidator:
    """Machine Learning-enhanced link validation and correction"""

    def __init__(self):
        self.domain_patterns = {
            'nvd': [
                'nvd.nist.gov',
                'cve.mitre.org',
                'cvedetails.com'
            ],
            'cisa': [
                'cisa.gov',
                'us-cert.gov'
            ],
            'security_news': [
                'bleepingcomputer.com',
                'krebsonsecurity.com',
                'threatpost.com',
                'securityweek.com'
            ],
            'frameworks': [
                'nist.gov',
                'iso.org',
                'cisecurity.org',
                'owasp.org'
            ]
        }

        self.url_templates = {
            'cve': [
                'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}',
                'https://www.cvedetails.com/cve/{cve_id}/'
            ],
            'cisa_advisory': [
                'https://www.cisa.gov/news-events/alerts/{year}/{month}/{day}/{advisory_id}',
                'https://www.cisa.gov/uscert/ncas/alerts/{advisory_id}'
            ]
        }

        # ML-like scoring for link quality
        self.quality_factors = {
            'https': 0.2,
            'official_domain': 0.3,
            'path_relevance': 0.25,
            'freshness': 0.15,
            'accessibility': 0.1
        }

    def validate_and_fix_cve_links(self, cve_data: List[Dict]) -> List[Dict]:
        """Validate and fix CVE links using ML techniques"""
        enhanced_cve_data = []

        for cve in cve_data:
            cve_id = cve.get('cve_id', '')

            # Generate multiple potential URLs
            potential_urls = self._generate_cve_urls(cve_id)

            # Score and validate URLs
            best_url = self._find_best_url(potential_urls, cve_id)

            # Enhanced CVE data
            enhanced_cve = cve.copy()
            enhanced_cve['primary_url'] = best_url
            enhanced_cve['alternative_urls'] = potential_urls[:3]  # Top 3 alternatives
            enhanced_cve['url_confidence'] = self._calculate_url_confidence(best_url, cve_id)

            enhanced_cve_data.append(enhanced_cve)

        return enhanced_cve_data

    def _generate_cve_urls(self, cve_id: str) -> List[str]:
        """Generate potential URLs for a CVE"""
        urls = []

        if cve_id and cve_id.startswith('CVE-'):
            # Primary sources
            urls.extend([
                f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}',
                f'https://www.cvedetails.com/cve/{cve_id}/',
                f'https://cve.circl.lu/cve/{cve_id}',
                f'https://vuldb.com/?id.{cve_id.replace("CVE-", "").replace("-", ".")}',
                f'https://www.opencve.io/cve/{cve_id}'
            ])

            # Secondary sources
            urls.extend([
                f'https://security.snyk.io/vuln/{cve_id}',
                f'https://www.rapid7.com/db/vulnerabilities/{cve_id}',
                f'https://www.exploit-db.com/search?cve={cve_id}'
            ])

        return urls

    def _find_best_url(self, urls: List[str], cve_id: str) -> str:
        """Find the best URL using ML-like scoring"""
        if not urls:
            return ''

        scored_urls = []

        for url in urls:
            score = self._score_url(url, cve_id)
            scored_urls.append((url, score))

        # Sort by score (highest first)
        scored_urls.sort(key=lambda x: x[1], reverse=True)

        return scored_urls[0][0] if scored_urls else urls[0]

    def _score_url(self, url: str, context: str) -> float:
        """Score URL quality using multiple factors"""
        score = 0.0

        # HTTPS bonus
        if url.startswith('https://'):
            score += self.quality_factors['https']

        # Official domain bonus
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()

        for category, domains in self.domain_patterns.items():
            for domain_pattern in domains:
                if domain_pattern in domain:
                    score += self.quality_factors['official_domain']
                    break

        # Path relevance
        if context.lower() in url.lower():
            score += self.quality_factors['path_relevance']

        # Domain authority (simplified)
        authority_domains = ['nist.gov', 'mitre.org', 'cisa.gov']
        if any(auth_domain in domain for auth_domain in authority_domains):
            score += 0.1

        return score

    def _calculate_url_confidence(self, url: str, context: str) -> float:
        """Calculate confidence score for URL (0-1)"""
        if not url:
            return 0.0

        confidence = 0.5  # Base confidence

        # Boost for official sources
        if any(domain in url for domain in ['nist.gov', 'mitre.org', 'cisa.gov']):
            confidence += 0.3

        # Boost for HTTPS
        if url.startswith('https://'):
            confidence += 0.1

        # Boost for context match
        if context.lower() in url.lower():
            confidence += 0.1

        return min(confidence, 1.0)

    def smart_search_links(self, query: str, content_type: str = 'general') -> List[Dict]:
        """Smart search for relevant links using web scraping"""
        search_results = []

        try:
            # Generate search URLs for different engines
            search_engines = self._get_search_urls(query, content_type)

            for engine, url in search_engines.items():
                try:
                    # Note: In production, you'd want to respect robots.txt and rate limits
                    response = requests.get(url, timeout=10, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    })

                    if response.status_code == 200:
                        links = self._extract_relevant_links(response.text, query, content_type)
                        search_results.extend(links)

                except Exception as e:
                    print(f"Error searching {engine}: {e}")
                    continue

            # Score and rank results
            scored_results = self._rank_search_results(search_results, query)

            return scored_results[:10]  # Top 10 results

        except Exception as e:
            print(f"Error in smart search: {e}")
            return []

    def _get_search_urls(self, query: str, content_type: str) -> Dict[str, str]:
        """Generate search URLs for different engines"""
        encoded_query = urllib.parse.quote_plus(query)

        urls = {
            'google': f'https://www.google.com/search?q={encoded_query}',
        }

        # Add specialized searches based on content type
        if content_type == 'cve':
            urls[
                'nvd'] = f'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cve_id={encoded_query}'
        elif content_type == 'security_news':
            urls[
                'security_search'] = f'https://www.google.com/search?q={encoded_query}+site:bleepingcomputer.com+OR+site:krebsonsecurity.com'

        return urls

    def _extract_relevant_links(self, html_content: str, query: str, content_type: str) -> List[Dict]:
        """Extract relevant links from HTML content"""
        # This is a simplified implementation
        # In production, you'd use proper HTML parsing

        links = []

        # Basic regex to find URLs (simplified)
        url_pattern = r'https?://[^\s<>"\']+[^\s<>"\',.]'
        found_urls = re.findall(url_pattern, html_content)

        for url in found_urls:
            relevance_score = self._calculate_relevance(url, query, content_type)
            if relevance_score > 0.3:  # Threshold for relevance
                links.append({
                    'url': url,
                    'relevance_score': relevance_score,
                    'title': self._extract_title_for_url(html_content, url),
                    'description': self._extract_description_for_url(html_content, url)
                })

        return links

    def _calculate_relevance(self, url: str, query: str, content_type: str) -> float:
        """Calculate relevance score for a URL"""
        score = 0.0

        # Query term matching
        query_terms = query.lower().split()
        url_lower = url.lower()

        for term in query_terms:
            if term in url_lower:
                score += 0.2

        # Domain authority
        high_authority_domains = [
            'nist.gov', 'mitre.org', 'cisa.gov', 'owasp.org',
            'sans.org', 'cert.org', 'cve.org'
        ]

        for domain in high_authority_domains:
            if domain in url_lower:
                score += 0.3
                break

        # Content type specific scoring
        if content_type == 'cve' and any(pattern in url_lower for pattern in ['cve', 'vuln', 'security']):
            score += 0.2

        return min(score, 1.0)

    def _extract_title_for_url(self, html_content: str, url: str) -> str:
        """Extract title for a specific URL from HTML"""
        # Simplified implementation
        return url.split('/')[-1] if url else "Link"

    def _extract_description_for_url(self, html_content: str, url: str) -> str:
        """Extract description for a specific URL from HTML"""
        # Simplified implementation
        return "Relevant security resource"

    def _rank_search_results(self, results: List[Dict], query: str) -> List[Dict]:
        """Rank search results by relevance"""
        return sorted(results, key=lambda x: x.get('relevance_score', 0), reverse=True)