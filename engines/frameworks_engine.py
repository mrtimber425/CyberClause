from .base_engine import BaseEngine
from typing import List, Dict
from datetime import datetime, timedelta


class FrameworksEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(hours=8)

    def refresh_data(self) -> bool:
        """Refresh frameworks data"""
        try:
            print("Refreshing frameworks data...")

            # Static frameworks data - in a real implementation, this would fetch from APIs
            frameworks = self._get_static_frameworks()

            # Store each framework
            for framework in frameworks:
                framework_id = f"{framework['organization']}_{framework['name'].replace(' ', '_')}"
                self.storage.store_data('frameworks', framework_id, framework)

            # Cache the complete list
            self.storage.cache_set('all_frameworks', frameworks, timedelta(hours=8))

            self.last_refresh = datetime.now()
            print(f"Refreshed {len(frameworks)} frameworks")
            return True

        except Exception as e:
            print(f"Error refreshing frameworks: {e}")
            return False

    def _get_static_frameworks(self) -> List[Dict]:
        """Get static frameworks data"""
        return [
            {
                'name': 'NIST Cybersecurity Framework',
                'version': '2.0',
                'organization': 'NIST',
                'last_updated': '2024-02-26',
                'functions': ['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
                'description': 'Framework for managing and reducing cybersecurity risk with enhanced governance.',
                'category': 'Risk Management',
                'maturity_levels': ['Partial', 'Risk Informed', 'Repeatable', 'Adaptive'],
                'url': 'https://www.nist.gov/cyberframework'
            },
            {
                'name': 'ISO/IEC 27001:2022',
                'version': '2022',
                'organization': 'ISO',
                'last_updated': '2022-10-25',
                'functions': ['ISMS Planning', 'Risk Assessment', 'Control Implementation', 'Monitoring',
                              'Improvement'],
                'description': 'International standard for information security management systems.',
                'category': 'Information Security',
                'maturity_levels': ['Initial', 'Managed', 'Defined', 'Quantitatively Managed', 'Optimizing'],
                'url': 'https://www.iso.org/standard/27001'
            },
            {
                'name': 'MITRE ATT&CK',
                'version': 'v14.1',
                'organization': 'MITRE',
                'last_updated': '2024-01-30',
                'functions': ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
                              'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
                              'Exfiltration', 'Impact'],
                'description': 'Knowledge base of adversary tactics and techniques based on real-world observations.',
                'category': 'Threat Intelligence',
                'maturity_levels': ['Basic', 'Intermediate', 'Advanced'],
                'url': 'https://attack.mitre.org/'
            },
            {
                'name': 'COBIT 2019',
                'version': '2019',
                'organization': 'ISACA',
                'last_updated': '2023-11-15',
                'functions': ['Evaluate Direct Monitor', 'Align Plan Organize', 'Build Acquire Implement',
                              'Deliver Service Support', 'Monitor Evaluate Assess'],
                'description': 'Framework for IT governance and management.',
                'category': 'IT Governance',
                'maturity_levels': ['Incomplete', 'Initial', 'Managed', 'Established', 'Predictable', 'Optimizing'],
                'url': 'https://www.isaca.org/resources/cobit'
            },
            {
                'name': 'Zero Trust Architecture',
                'version': '2.0',
                'organization': 'NIST',
                'last_updated': '2024-01-20',
                'functions': ['Identity', 'Device', 'Network', 'Application Workload', 'Data'],
                'description': 'Never trust, always verify security architecture framework.',
                'category': 'Architecture',
                'maturity_levels': ['Traditional', 'Initial', 'Advanced', 'Optimal'],
                'url': 'https://www.nist.gov/publications/zero-trust-architecture'
            },
            {
                'name': 'Essential Eight',
                'version': '2023',
                'organization': 'Australian Cyber Security Centre',
                'last_updated': '2024-01-15',
                'functions': ['Application Control', 'Patch Applications', 'Configure Microsoft Office',
                              'User Application Hardening', 'Restrict Admin Privileges', 'Patch Operating Systems',
                              'Multi-factor Authentication', 'Regular Backups'],
                'description': 'Eight essential cyber security mitigation strategies.',
                'category': 'Cyber Security',
                'maturity_levels': ['Maturity Level One', 'Maturity Level Two', 'Maturity Level Three'],
                'url': 'https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight'
            },
            {
                'name': 'CIS Controls',
                'version': 'v8',
                'organization': 'Center for Internet Security',
                'last_updated': '2021-05-18',
                'functions': ['Basic CIS Controls', 'Foundational CIS Controls', 'Organizational CIS Controls'],
                'description': 'Prioritized set of actions for cyber defense.',
                'category': 'Cyber Defense',
                'maturity_levels': ['Implementation Group 1', 'Implementation Group 2', 'Implementation Group 3'],
                'url': 'https://www.cisecurity.org/controls/'
            }
        ]

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get frameworks data with optional filtering"""
        # Try to get from cache first
        cached_data = self.storage.cache_get('all_frameworks')

        if cached_data is None or self.needs_refresh():
            # Refresh if needed
            if not self.refresh_data():
                # Fall back to stored data
                cached_data = self.storage.get_data('frameworks')
            else:
                cached_data = self.storage.cache_get('all_frameworks') or []

        # Apply filters if provided
        if filters:
            cached_data = self.filter_data(cached_data, filters)

        # Sort by last updated (newest first)
        cached_data.sort(key=lambda x: x.get('last_updated', ''), reverse=True)

        return cached_data

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search frameworks"""
        all_data = self.get_data()

        # Filter by search query
        search_filters = {'search': query}
        if filters:
            search_filters.update(filters)

        return self.filter_data(all_data, search_filters)

    def get_by_category(self, category: str) -> List[Dict]:
        """Get frameworks by category"""
        filters = {'category': category}
        return self.get_data(filters)