from .base_engine import BaseEngine
import requests
from bs4 import BeautifulSoup
from typing import List, Dict
from datetime import datetime, timedelta
import re


class PoliciesEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(hours=4)

        # Define policy sources
        self.policy_sources = {
            'NIST': {
                'url': 'https://www.nist.gov/cyberframework/framework',
                'type': 'Framework'
            },
            'CISA': {
                'url': 'https://www.cisa.gov/resources-tools/resources',
                'type': 'Government'
            },
            'Australian Cyber Security Centre': {
                'url': 'https://www.cyber.gov.au/resources-business-and-government',
                'type': 'Government'
            }
        }

    def refresh_data(self) -> bool:
        """Refresh policies and documentation from various sources"""
        try:
            print("Refreshing policies data...")

            # Static policy data - in a real implementation, this would scrape/API call
            policies = self._get_static_policies()

            # Store each policy
            for policy in policies:
                policy_id = f"{policy['organization']}_{hash(policy['title'])}"
                self.storage.store_data('policies', policy_id, policy)

            # Cache the complete list
            self.storage.cache_set('all_policies', policies, timedelta(hours=4))

            self.last_refresh = datetime.now()
            print(f"Refreshed {len(policies)} policies")
            return True

        except Exception as e:
            print(f"Error refreshing policies: {e}")
            return False

    def _get_static_policies(self) -> List[Dict]:
        """Get static policy data - replace with real API calls"""
        return [
            {
                'title': 'NIST Cybersecurity Framework 2.0',
                'organization': 'NIST',
                'category': 'Framework',
                'last_updated': '2024-02-26',
                'description': 'Updated framework for managing and reducing cybersecurity risk with new Govern function.',
                'url': 'https://www.nist.gov/cyberframework',
                'document_type': 'Framework',
                'compliance_level': 'Voluntary'
            },
            {
                'title': 'Essential Eight Maturity Model',
                'organization': 'Australian Cyber Security Centre',
                'category': 'Government',
                'last_updated': '2024-01-15',
                'description': 'Strategies to mitigate cyber security incidents in Australian organizations.',
                'url': 'https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight',
                'document_type': 'Guidelines',
                'compliance_level': 'Recommended'
            },
            {
                'title': 'CISA Cybersecurity Performance Goals',
                'organization': 'CISA',
                'category': 'Government',
                'last_updated': '2023-11-30',
                'description': 'Baseline cybersecurity practices for critical infrastructure.',
                'url': 'https://www.cisa.gov/cross-sector-cybersecurity-performance-goals',
                'document_type': 'Guidelines',
                'compliance_level': 'Recommended'
            },
            {
                'title': 'ISO/IEC 27001:2022 Information Security Management',
                'organization': 'ISO',
                'category': 'Standards',
                'last_updated': '2022-10-25',
                'description': 'International standard for information security management systems.',
                'url': 'https://www.iso.org/standard/27001',
                'document_type': 'Standard',
                'compliance_level': 'Voluntary'
            },
            {
                'title': 'GDPR Compliance Guidelines',
                'organization': 'European Union',
                'category': 'Privacy',
                'last_updated': '2024-01-10',
                'description': 'General Data Protection Regulation compliance requirements.',
                'url': 'https://gdpr.eu/compliance/',
                'document_type': 'Regulation',
                'compliance_level': 'Mandatory'
            },
            {
                'title': 'HIPAA Security Rule Implementation',
                'organization': 'HHS',
                'category': 'Healthcare',
                'last_updated': '2024-02-01',
                'description': 'Health Insurance Portability and Accountability Act security requirements.',
                'url': 'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
                'document_type': 'Regulation',
                'compliance_level': 'Mandatory'
            },
            {
                'title': 'PCI DSS v4.0 Requirements',
                'organization': 'PCI Security Standards Council',
                'category': 'Financial',
                'last_updated': '2024-01-30',
                'description': 'Payment Card Industry Data Security Standard version 4.0.',
                'url': 'https://www.pcisecuritystandards.org/pci_security/',
                'document_type': 'Standard',
                'compliance_level': 'Mandatory'
            },
            {
                'title': 'SOX IT Controls Framework',
                'organization': 'SEC',
                'category': 'Financial',
                'last_updated': '2023-12-20',
                'description': 'Sarbanes-Oxley Act IT control requirements for financial reporting.',
                'url': 'https://www.sec.gov/about/laws/soa2002.pdf',
                'document_type': 'Regulation',
                'compliance_level': 'Mandatory'
            }
        ]

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get policies data with optional filtering"""
        # Try to get from cache first
        cached_data = self.storage.cache_get('all_policies')

        if cached_data is None or self.needs_refresh():
            # Refresh if needed
            if not self.refresh_data():
                # Fall back to stored data
                cached_data = self.storage.get_data('policies')
            else:
                cached_data = self.storage.cache_get('all_policies') or []

        # Apply filters if provided
        if filters:
            cached_data = self.filter_data(cached_data, filters)

        # Sort by last updated (newest first)
        cached_data.sort(key=lambda x: x.get('last_updated', ''), reverse=True)

        return cached_data

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search policies"""
        all_data = self.get_data()

        # Filter by search query
        search_filters = {'search': query}
        if filters:
            search_filters.update(filters)

        return self.filter_data(all_data, search_filters)

    def get_by_organization(self, organization: str) -> List[Dict]:
        """Get policies by organization"""
        all_data = self.get_data()
        return [item for item in all_data if item.get('organization', '').lower() == organization.lower()]
