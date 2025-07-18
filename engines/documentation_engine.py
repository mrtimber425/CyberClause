from .base_engine import BaseEngine
from typing import List, Dict
from datetime import datetime, timedelta


class DocumentationEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(hours=6)

    def refresh_data(self) -> bool:
        """Refresh documentation data"""
        try:
            print("Refreshing documentation data...")

            # Static documentation data
            documentation = self._get_static_documentation()

            # Store each document
            for doc in documentation:
                doc_id = f"{doc['source']}_{hash(doc['title'])}"
                self.storage.store_data('documentation', doc_id, doc)

            # Cache the complete list
            self.storage.cache_set('all_documentation', documentation, timedelta(hours=6))

            self.last_refresh = datetime.now()
            print(f"Refreshed {len(documentation)} documentation items")
            return True

        except Exception as e:
            print(f"Error refreshing documentation: {e}")
            return False

    def _get_static_documentation(self) -> List[Dict]:
        """Get static documentation data"""
        return [
            {
                'title': 'OWASP Top 10 - 2021',
                'category': 'Web Security',
                'source': 'OWASP',
                'last_updated': '2021-09-24',
                'description': 'The top 10 web application security risks for 2021.',
                'url': 'https://owasp.org/Top10/',
                'document_type': 'Guidelines',
                'format': 'Web/PDF'
            },
            {
                'title': 'CIS Controls v8',
                'category': 'Security Controls',
                'source': 'Center for Internet Security',
                'last_updated': '2021-05-18',
                'description': 'Prioritized set of actions for cyber defense to stop today\'s most pervasive attacks.',
                'url': 'https://www.cisecurity.org/controls/',
                'document_type': 'Framework',
                'format': 'PDF/Web'
            },
            {
                'title': 'SANS Top 25 Software Errors',
                'category': 'Secure Coding',
                'source': 'SANS',
                'last_updated': '2023-06-15',
                'description': 'Most dangerous software security errors that lead to serious vulnerabilities.',
                'url': 'https://www.sans.org/top25-software-errors/',
                'document_type': 'Guidelines',
                'format': 'Web'
            },
            {
                'title': 'NIST Cloud Security Guide SP 800-144',
                'category': 'Cloud Security',
                'source': 'NIST',
                'last_updated': '2024-01-15',
                'description': 'Guidelines for security and privacy in public cloud computing.',
                'url': 'https://csrc.nist.gov/publications/detail/sp/800-144/final',
                'document_type': 'Guidelines',
                'format': 'PDF'
            },
            {
                'title': 'CISA Incident Response Playbook',
                'category': 'Incident Response',
                'source': 'CISA',
                'last_updated': '2024-02-10',
                'description': 'Federal government cybersecurity incident response playbook.',
                'url': 'https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_Response_Playbook_508.pdf',
                'document_type': 'Playbook',
                'format': 'PDF'
            },
            {
                'title': 'MITRE ATT&CK for Enterprise',
                'category': 'Threat Intelligence',
                'source': 'MITRE',
                'last_updated': '2024-01-30',
                'description': 'Knowledge base of adversary tactics and techniques for enterprise environments.',
                'url': 'https://attack.mitre.org/matrices/enterprise/',
                'document_type': 'Knowledge Base',
                'format': 'Web/JSON'
            },
            {
                'title': 'Zero Trust Maturity Model',
                'category': 'Architecture',
                'source': 'CISA',
                'last_updated': '2023-09-12',
                'description': 'Maturity model for zero trust architecture implementation.',
                'url': 'https://www.cisa.gov/sites/default/files/publications/CISA%20Zero%20Trust%20Maturity%20Model_Draft.pdf',
                'document_type': 'Model',
                'format': 'PDF'
            },
            {
                'title': 'AWS Security Best Practices',
                'category': 'Cloud Security',
                'source': 'AWS',
                'last_updated': '2024-01-08',
                'description': 'Security best practices for Amazon Web Services cloud platform.',
                'url': 'https://aws.amazon.com/architecture/security-identity-compliance/',
                'document_type': 'Best Practices',
                'format': 'Web'
            }
        ]

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get documentation data with optional filtering"""
        # Try to get from cache first
        cached_data = self.storage.cache_get('all_documentation')

        if cached_data is None or self.needs_refresh():
            # Refresh if needed
            if not self.refresh_data():
                # Fall back to stored data
                cached_data = self.storage.get_data('documentation')
            else:
                cached_data = self.storage.cache_get('all_documentation') or []

        # Apply filters if provided
        if filters:
            cached_data = self.filter_data(cached_data, filters)

        # Sort by last updated (newest first)
        cached_data.sort(key=lambda x: x.get('last_updated', ''), reverse=True)

        return cached_data

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search documentation"""
        all_data = self.get_data()

        # Filter by search query
        search_filters = {'search': query}
        if filters:
            search_filters.update(filters)

        return self.filter_data(all_data, search_filters)
