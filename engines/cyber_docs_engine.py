from .base_engine import BaseEngine
from typing import List, Dict
from datetime import datetime, timedelta


class CyberDocsEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(hours=6)

    def refresh_data(self) -> bool:
        """Refresh all cybersecurity documents"""
        try:
            print("Refreshing cybersecurity documents...")

            all_docs = []

            # Get all document types
            policies = self._get_static_policies()
            frameworks = self._get_static_frameworks()
            documentation = self._get_static_documentation()
            standards = self._get_static_standards()
            guidelines = self._get_static_guidelines()

            all_docs.extend(policies)
            all_docs.extend(frameworks)
            all_docs.extend(documentation)
            all_docs.extend(standards)
            all_docs.extend(guidelines)

            # Store each document
            for doc in all_docs:
                doc_id = f"{doc['document_type']}_{doc['source']}_{hash(doc['title'])}"
                if self.storage:
                    self.storage.store_data('cyber_docs', doc_id, doc)

            # Cache the complete list
            if self.storage:
                self.storage.cache_set('all_cyber_docs', all_docs, timedelta(hours=6))

            self.last_refresh = datetime.now()
            self.cached_docs = all_docs  # Store in memory for web API
            print(f"Refreshed {len(all_docs)} cybersecurity documents")
            return True

        except Exception as e:
            print(f"Error refreshing cybersecurity documents: {e}")
            return False

    def _get_static_policies(self) -> List[Dict]:
        """Get cybersecurity policies"""
        return [
            {
                'title': 'NIST Cybersecurity Framework 2.0',
                'source': 'NIST',
                'document_type': 'Framework',
                'category': 'Risk Management',
                'subcategory': 'Enterprise Security',
                'last_updated': '2024-02-26',
                'description': 'Updated framework for managing and reducing cybersecurity risk with new Govern function.',
                'url': 'https://www.nist.gov/cyberframework',
                'compliance_level': 'Voluntary',
                'industry': 'All',
                'region': 'Global',
                'tags': ['framework', 'risk management', 'governance'],
                'key_features': ['Govern Function', 'Risk Assessment', 'Implementation Guidance']
            },
            {
                'title': 'Essential Eight Maturity Model',
                'source': 'Australian Cyber Security Centre',
                'document_type': 'Framework',
                'category': 'Security Controls',
                'subcategory': 'Mitigation Strategies',
                'last_updated': '2024-01-15',
                'description': 'Eight strategies to mitigate cyber security incidents in Australian organizations.',
                'url': 'https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight',
                'compliance_level': 'Recommended',
                'industry': 'All',
                'region': 'Australia',
                'tags': ['controls', 'mitigation', 'maturity'],
                'key_features': ['Application Control', 'Patch Management', 'Multi-factor Authentication']
            },
            {
                'title': 'GDPR Compliance Guidelines',
                'source': 'European Union',
                'document_type': 'Regulation',
                'category': 'Privacy',
                'subcategory': 'Data Protection',
                'last_updated': '2024-01-10',
                'description': 'General Data Protection Regulation compliance requirements for EU operations.',
                'url': 'https://gdpr.eu/compliance/',
                'compliance_level': 'Mandatory',
                'industry': 'All',
                'region': 'European Union',
                'tags': ['privacy', 'data protection', 'compliance'],
                'key_features': ['Data Rights', 'Breach Notification', 'Privacy by Design']
            },
            {
                'title': 'HIPAA Security Rule',
                'source': 'HHS',
                'document_type': 'Regulation',
                'category': 'Healthcare',
                'subcategory': 'Patient Data Security',
                'last_updated': '2024-02-01',
                'description': 'Health Insurance Portability and Accountability Act security requirements.',
                'url': 'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
                'compliance_level': 'Mandatory',
                'industry': 'Healthcare',
                'region': 'United States',
                'tags': ['healthcare', 'compliance', 'privacy'],
                'key_features': ['Administrative Safeguards', 'Physical Safeguards', 'Technical Safeguards']
            },
            {
                'title': 'SOX IT Controls Framework',
                'source': 'SEC',
                'document_type': 'Regulation',
                'category': 'Financial',
                'subcategory': 'Financial Reporting',
                'last_updated': '2023-12-20',
                'description': 'Sarbanes-Oxley Act IT control requirements for financial reporting accuracy.',
                'url': 'https://www.sec.gov/about/laws/soa2002.pdf',
                'compliance_level': 'Mandatory',
                'industry': 'Financial Services',
                'region': 'United States',
                'tags': ['financial', 'controls', 'reporting'],
                'key_features': ['IT General Controls', 'Application Controls', 'Data Integrity']
            }
        ]

    def _get_static_frameworks(self) -> List[Dict]:
        """Get cybersecurity frameworks"""
        return [
            {
                'title': 'MITRE ATT&CK for Enterprise',
                'source': 'MITRE',
                'document_type': 'Framework',
                'category': 'Threat Intelligence',
                'subcategory': 'Tactics & Techniques',
                'last_updated': '2024-01-30',
                'description': 'Comprehensive knowledge base of adversary tactics and techniques for enterprise environments.',
                'url': 'https://attack.mitre.org/matrices/enterprise/',
                'compliance_level': 'Voluntary',
                'industry': 'All',
                'region': 'Global',
                'tags': ['threat intelligence', 'tactics', 'techniques'],
                'key_features': ['14 Tactics', '200+ Techniques', 'Threat Mapping']
            },
            {
                'title': 'CIS Controls v8',
                'source': 'Center for Internet Security',
                'document_type': 'Framework',
                'category': 'Security Controls',
                'subcategory': 'Implementation Guide',
                'last_updated': '2021-05-18',
                'description': 'Prioritized set of actions for cyber defense to stop today\'s most pervasive attacks.',
                'url': 'https://www.cisecurity.org/controls/',
                'compliance_level': 'Voluntary',
                'industry': 'All',
                'region': 'Global',
                'tags': ['controls', 'defense', 'implementation'],
                'key_features': ['18 Controls', 'Implementation Groups', 'Sub-Controls']
            },
            {
                'title': 'Zero Trust Architecture',
                'source': 'NIST',
                'document_type': 'Framework',
                'category': 'Architecture',
                'subcategory': 'Network Security',
                'last_updated': '2024-01-20',
                'description': 'Never trust, always verify security architecture framework.',
                'url': 'https://www.nist.gov/publications/zero-trust-architecture',
                'compliance_level': 'Voluntary',
                'industry': 'All',
                'region': 'Global',
                'tags': ['zero trust', 'architecture', 'network security'],
                'key_features': ['Identity Verification', 'Device Trust', 'Network Segmentation']
            }
        ]

    def _get_static_documentation(self) -> List[Dict]:
        """Get cybersecurity documentation"""
        return [
            {
                'title': 'OWASP Top 10 - 2021',
                'source': 'OWASP',
                'document_type': 'Guideline',
                'category': 'Web Security',
                'subcategory': 'Vulnerability Guide',
                'last_updated': '2021-09-24',
                'description': 'The top 10 web application security risks for 2021.',
                'url': 'https://owasp.org/Top10/',
                'compliance_level': 'Voluntary',
                'industry': 'Software Development',
                'region': 'Global',
                'tags': ['web security', 'vulnerabilities', 'development'],
                'key_features': ['Top 10 Risks', 'Prevention Guides', 'Testing Methods']
            },
            {
                'title': 'SANS Top 25 Software Errors',
                'source': 'SANS',
                'document_type': 'Guideline',
                'category': 'Secure Coding',
                'subcategory': 'Best Practices',
                'last_updated': '2023-06-15',
                'description': 'Most dangerous software security errors that lead to serious vulnerabilities.',
                'url': 'https://www.sans.org/top25-software-errors/',
                'compliance_level': 'Voluntary',
                'industry': 'Software Development',
                'region': 'Global',
                'tags': ['secure coding', 'software errors', 'development'],
                'key_features': ['Common Weaknesses', 'Mitigation Strategies', 'Code Examples']
            },
            {
                'title': 'CISA Incident Response Playbook',
                'source': 'CISA',
                'document_type': 'Playbook',
                'category': 'Incident Response',
                'subcategory': 'Government Guide',
                'last_updated': '2024-02-10',
                'description': 'Federal government cybersecurity incident response playbook.',
                'url': 'https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_Response_Playbook_508.pdf',
                'compliance_level': 'Recommended',
                'industry': 'Government',
                'region': 'United States',
                'tags': ['incident response', 'playbook', 'government'],
                'key_features': ['Response Phases', 'Coordination', 'Recovery Procedures']
            }
        ]

    def _get_static_standards(self) -> List[Dict]:
        """Get cybersecurity standards"""
        return [
            {
                'title': 'ISO/IEC 27001:2022',
                'source': 'ISO',
                'document_type': 'Standard',
                'category': 'Information Security',
                'subcategory': 'Management System',
                'last_updated': '2022-10-25',
                'description': 'International standard for information security management systems.',
                'url': 'https://www.iso.org/standard/27001',
                'compliance_level': 'Voluntary',
                'industry': 'All',
                'region': 'Global',
                'tags': ['ISO', 'information security', 'management system'],
                'key_features': ['ISMS Requirements', 'Risk Assessment', 'Continuous Improvement']
            },
            {
                'title': 'PCI DSS v4.0',
                'source': 'PCI Security Standards Council',
                'document_type': 'Standard',
                'category': 'Financial',
                'subcategory': 'Payment Security',
                'last_updated': '2024-01-30',
                'description': 'Payment Card Industry Data Security Standard version 4.0.',
                'url': 'https://www.pcisecuritystandards.org/pci_security/',
                'compliance_level': 'Mandatory',
                'industry': 'Financial Services',
                'region': 'Global',
                'tags': ['payments', 'compliance', 'financial'],
                'key_features': ['12 Requirements', 'Network Security', 'Cardholder Data Protection']
            },
            {
                'title': 'SOC 2 Type II',
                'source': 'AICPA',
                'document_type': 'Standard',
                'category': 'Audit',
                'subcategory': 'Service Organizations',
                'last_updated': '2023-12-01',
                'description': 'Service Organization Control 2 Type II audit framework.',
                'url': 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html',
                'compliance_level': 'Voluntary',
                'industry': 'Technology',
                'region': 'Global',
                'tags': ['audit', 'SOC 2', 'compliance'],
                'key_features': ['Trust Service Criteria', 'Security Controls', 'Availability']
            }
        ]

    def _get_static_guidelines(self) -> List[Dict]:
        """Get cybersecurity guidelines"""
        return [
            {
                'title': 'NIST Cloud Security Guide SP 800-144',
                'source': 'NIST',
                'document_type': 'Guideline',
                'category': 'Cloud Security',
                'subcategory': 'Implementation Guide',
                'last_updated': '2024-01-15',
                'description': 'Guidelines for security and privacy in public cloud computing.',
                'url': 'https://csrc.nist.gov/publications/detail/sp/800-144/final',
                'compliance_level': 'Recommended',
                'industry': 'All',
                'region': 'Global',
                'tags': ['cloud security', 'NIST', 'implementation'],
                'key_features': ['Cloud Models', 'Security Architecture', 'Risk Assessment']
            },
            {
                'title': 'AWS Security Best Practices',
                'source': 'AWS',
                'document_type': 'Guideline',
                'category': 'Cloud Security',
                'subcategory': 'Platform Specific',
                'last_updated': '2024-01-08',
                'description': 'Security best practices for Amazon Web Services cloud platform.',
                'url': 'https://aws.amazon.com/architecture/security-identity-compliance/',
                'compliance_level': 'Recommended',
                'industry': 'Cloud Computing',
                'region': 'Global',
                'tags': ['AWS', 'cloud security', 'best practices'],
                'key_features': ['Identity Management', 'Data Protection', 'Monitoring']
            },
            {
                'title': 'Microsoft Azure Security Center',
                'source': 'Microsoft',
                'document_type': 'Guideline',
                'category': 'Cloud Security',
                'subcategory': 'Platform Specific',
                'last_updated': '2024-01-12',
                'description': 'Security guidelines and best practices for Microsoft Azure.',
                'url': 'https://docs.microsoft.com/en-us/azure/security/',
                'compliance_level': 'Recommended',
                'industry': 'Cloud Computing',
                'region': 'Global',
                'tags': ['Azure', 'Microsoft', 'cloud security'],
                'key_features': ['Security Baseline', 'Threat Protection', 'Compliance Tools']
            }
        ]

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get cybersecurity documents with optional filtering"""
        # Try to get from cache first
        if self.storage:
            cached_data = self.storage.cache_get('all_cyber_docs')
        else:
            cached_data = getattr(self, 'cached_docs', None)

        if cached_data is None or self.needs_refresh():
            # Refresh if needed
            if not self.refresh_data():
                # Fall back to stored data
                if self.storage:
                    cached_data = self.storage.get_data('cyber_docs')
                else:
                    cached_data = []
            else:
                if self.storage:
                    cached_data = self.storage.cache_get('all_cyber_docs') or []
                else:
                    cached_data = getattr(self, 'cached_docs', [])

        # Apply filters if provided
        if filters:
            cached_data = self.filter_data(cached_data, filters)

        # Sort by last updated (newest first)
        cached_data.sort(key=lambda x: x.get('last_updated', ''), reverse=True)

        return cached_data

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search cybersecurity documents"""
        all_data = self.get_data()

        # Filter by search query
        search_filters = {'search': query}
        if filters:
            search_filters.update(filters)

        return self.filter_data(all_data, search_filters)

    def get_by_category(self, category: str) -> List[Dict]:
        """Get documents by category"""
        filters = {'category': category}
        return self.get_data(filters)

    def get_by_document_type(self, doc_type: str) -> List[Dict]:
        """Get documents by type"""
        all_data = self.get_data()
        return [doc for doc in all_data if doc.get('document_type', '').lower() == doc_type.lower()]

    def get_by_industry(self, industry: str) -> List[Dict]:
        """Get documents by industry"""
        all_data = self.get_data()
        return [doc for doc in all_data if
                industry.lower() in doc.get('industry', '').lower() or
                doc.get('industry', '') == 'All']

    def get_by_compliance_level(self, compliance_level: str) -> List[Dict]:
        """Get documents by compliance level"""
        all_data = self.get_data()
        return [doc for doc in all_data if
                doc.get('compliance_level', '').lower() == compliance_level.lower()]

    def get_document_details(self, title: str) -> Dict:
        """Get detailed information for a specific document"""
        all_docs = self.get_data()

        for doc in all_docs:
            if doc.get('title', '').lower() == title.lower():
                # Enhance with additional details
                enhanced_doc = doc.copy()
                enhanced_doc['implementation_tips'] = self._get_implementation_tips(doc)
                enhanced_doc['related_documents'] = self._get_related_documents(doc, all_docs)
                return enhanced_doc

        return {}

    def _get_implementation_tips(self, doc: Dict) -> List[str]:
        """Get implementation tips based on document type"""
        doc_type = doc.get('document_type', '').lower()
        category = doc.get('category', '').lower()

        tips = []

        if 'framework' in doc_type:
            tips.extend([
                "Start with risk assessment and gap analysis",
                "Engage stakeholders across all business units",
                "Implement in phases with measurable milestones",
                "Regular review and continuous improvement"
            ])

        if 'standard' in doc_type:
            tips.extend([
                "Review current controls against standard requirements",
                "Document policies and procedures",
                "Train staff on new requirements",
                "Conduct regular audits and assessments"
            ])

        if 'regulation' in doc_type:
            tips.extend([
                "Understand legal requirements and penalties",
                "Implement compliance monitoring",
                "Maintain evidence of compliance",
                "Regular legal review and updates"
            ])

        return tips[:5]  # Limit to 5 tips

    def _get_related_documents(self, doc: Dict, all_docs: List[Dict]) -> List[Dict]:
        """Find related documents based on category and tags"""
        related = []
        doc_category = doc.get('category', '').lower()
        doc_tags = [tag.lower() for tag in doc.get('tags', [])]

        for other_doc in all_docs:
            if other_doc['title'] == doc['title']:
                continue

            # Check category match
            if other_doc.get('category', '').lower() == doc_category:
                related.append(other_doc)
                continue

            # Check tag overlap
            other_tags = [tag.lower() for tag in other_doc.get('tags', [])]
            if any(tag in other_tags for tag in doc_tags):
                related.append(other_doc)

        return related[:5]  # Limit to 5 related documents

    def get_document_statistics(self) -> Dict:
        """Get document statistics"""
        all_data = self.get_data()

        stats = {
            'total_documents': len(all_data),
            'by_type': {},
            'by_category': {},
            'by_industry': {},
            'by_compliance_level': {},
            'by_source': {},
            'recent_updates': 0
        }

        # Count by various categories
        for doc in all_data:
            # By type
            doc_type = doc.get('document_type', 'Unknown')
            stats['by_type'][doc_type] = stats['by_type'].get(doc_type, 0) + 1

            # By category
            category = doc.get('category', 'Unknown')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

            # By industry
            industry = doc.get('industry', 'Unknown')
            stats['by_industry'][industry] = stats['by_industry'].get(industry, 0) + 1

            # By compliance level
            compliance = doc.get('compliance_level', 'Unknown')
            stats['by_compliance_level'][compliance] = stats['by_compliance_level'].get(compliance, 0) + 1

            # By source
            source = doc.get('source', 'Unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

        # Recent updates (last 90 days)
        cutoff_date = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d')
        stats['recent_updates'] = len([
            doc for doc in all_data
            if doc.get('last_updated', '') >= cutoff_date
        ])

        return stats

    def get_available_filters(self) -> Dict:
        """Get all available filter options"""
        all_data = self.get_data()

        filters = {
            'document_types': list(set([doc.get('document_type', '') for doc in all_data])),
            'categories': list(set([doc.get('category', '') for doc in all_data])),
            'subcategories': list(set([doc.get('subcategory', '') for doc in all_data])),
            'industries': list(set([doc.get('industry', '') for doc in all_data])),
            'compliance_levels': list(set([doc.get('compliance_level', '') for doc in all_data])),
            'sources': list(set([doc.get('source', '') for doc in all_data])),
            'regions': list(set([doc.get('region', '') for doc in all_data]))
        }

        # Remove empty values and sort
        for key in filters:
            filters[key] = sorted([item for item in filters[key] if item])

        return filters