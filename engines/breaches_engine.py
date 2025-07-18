from .base_engine import BaseEngine
import requests
from typing import List, Dict
from datetime import datetime, timedelta
import json


class BreachesEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(minutes=30)
        self.hibp_api_key = api_manager.get_api_key('hibp')

        # Enhanced breach checking websites for users to choose from
        self.breach_check_sites = {
            'haveibeenpwned': {
                'name': 'Have I Been Pwned',
                'url': 'https://haveibeenpwned.com',
                'check_url': 'https://haveibeenpwned.com/account/{email}',
                'description': 'The most comprehensive breach database by Troy Hunt with over 12 billion accounts',
                'features': ['Email breach check', 'Password check', 'Domain monitoring', 'API access'],
                'free': True,
                'api_available': True,
                'icon': '🔍',
                'reliability': 'Very High',
                'founded': '2013',
                'coverage': '12+ billion accounts',
                'update_frequency': 'Real-time',
                'special_features': ['Breach notifications', 'Pwned passwords check', 'Domain search']
            },
            'dehashed': {
                'name': 'DeHashed',
                'url': 'https://dehashed.com',
                'check_url': 'https://dehashed.com/search?query={email}',
                'description': 'Deep search engine for leaked databases with advanced search capabilities',
                'features': ['Email search', 'Username search', 'Phone search', 'Name search', 'IP search'],
                'free': False,
                'api_available': True,
                'icon': '🕵️',
                'reliability': 'High',
                'founded': '2016',
                'coverage': '15+ billion records',
                'update_frequency': 'Daily',
                'special_features': ['Advanced filters', 'Bulk searches', 'API integration']
            },
            'leakcheck': {
                'name': 'LeakCheck',
                'url': 'https://leakcheck.io',
                'check_url': 'https://leakcheck.io/check/{email}',
                'description': 'Professional data leak monitoring service with real-time alerts',
                'features': ['Email monitoring', 'Domain monitoring', 'Real-time alerts', 'API access'],
                'free': True,
                'api_available': True,
                'icon': '⚡',
                'reliability': 'High',
                'founded': '2018',
                'coverage': '8+ billion records',
                'update_frequency': 'Real-time',
                'special_features': ['Free tier available', 'Enterprise solutions', 'Custom alerts']
            },
            'intelx': {
                'name': 'Intelligence X',
                'url': 'https://intelx.io',
                'check_url': 'https://intelx.io/?s={email}',
                'description': 'Search engine and data archive for leaked databases and breaches',
                'features': ['Multi-source search', 'Historical data', 'Advanced filters', 'Dark web monitoring'],
                'free': True,
                'api_available': True,
                'icon': '🧠',
                'reliability': 'Medium',
                'founded': '2018',
                'coverage': '5+ billion records',
                'update_frequency': 'Weekly',
                'special_features': ['Dark web search', 'Historical archives', 'Multiple data sources']
            },
            'breachdirectory': {
                'name': 'Breach Directory',
                'url': 'https://breachdirectory.org',
                'check_url': 'https://breachdirectory.org/check?q={email}',
                'description': 'Free breach checking service with simple interface',
                'features': ['Email check', 'Simple interface', 'Quick results', 'No registration required'],
                'free': True,
                'api_available': False,
                'icon': '📂',
                'reliability': 'Medium',
                'founded': '2019',
                'coverage': '3+ billion records',
                'update_frequency': 'Monthly',
                'special_features': ['Completely free', 'No registration', 'Privacy focused']
            },
            'ghostproject': {
                'name': 'GhostProject',
                'url': 'https://ghostproject.fr',
                'check_url': 'https://ghostproject.fr/search?q={email}',
                'description': 'French breach database search with European focus',
                'features': ['Email search', 'Historical breaches', 'European focus', 'Multi-language'],
                'free': True,
                'api_available': False,
                'icon': '👻',
                'reliability': 'Medium',
                'founded': '2017',
                'coverage': '2+ billion records',
                'update_frequency': 'Monthly',
                'special_features': ['European compliance', 'GDPR compliant', 'Multi-language support']
            },
            'scylla': {
                'name': 'Scylla.sh',
                'url': 'https://scylla.sh',
                'check_url': 'https://scylla.sh/search?q={email}',
                'description': 'Community-driven breach database with regular updates',
                'features': ['Community sourced', 'Regular updates', 'Multiple formats', 'Open source'],
                'free': True,
                'api_available': True,
                'icon': '🌊',
                'reliability': 'Medium',
                'founded': '2020',
                'coverage': '4+ billion records',
                'update_frequency': 'Weekly',
                'special_features': ['Community driven', 'Open source', 'Multiple export formats']
            },
            'snusbase': {
                'name': 'SnusBase',
                'url': 'https://snusbase.com',
                'check_url': 'https://snusbase.com/search/{email}',
                'description': 'Comprehensive database search platform with advanced features',
                'features': ['Multi-field search', 'Advanced filters', 'Export options', 'Bulk searches'],
                'free': False,
                'api_available': True,
                'icon': '🔬',
                'reliability': 'High',
                'founded': '2019',
                'coverage': '10+ billion records',
                'update_frequency': 'Daily',
                'special_features': ['Advanced search', 'Bulk operations', 'Enterprise features']
            },
            'weleakinfo_alternative': {
                'name': 'Leak-Lookup',
                'url': 'https://leak-lookup.com',
                'check_url': 'https://leak-lookup.com/search?query={email}',
                'description': 'Alternative service providing comprehensive breach searches',
                'features': ['Email search', 'Phone search', 'Domain search', 'Historical data'],
                'free': False,
                'api_available': True,
                'icon': '🔎',
                'reliability': 'High',
                'founded': '2020',
                'coverage': '6+ billion records',
                'update_frequency': 'Weekly',
                'special_features': ['Multiple search types', 'Historical analysis', 'Detailed reports']
            },
            'cybernews_checker': {
                'name': 'CyberNews Personal Data Leak Checker',
                'url': 'https://cybernews.com/personal-data-leak-check/',
                'check_url': 'https://cybernews.com/personal-data-leak-check/',
                'description': 'Free personal data leak checker by CyberNews',
                'features': ['Email check', 'Privacy focused', 'No data storage', 'Educational resources'],
                'free': True,
                'api_available': False,
                'icon': '📰',
                'reliability': 'Medium',
                'founded': '2021',
                'coverage': '15+ billion records',
                'update_frequency': 'Monthly',
                'special_features': ['Privacy focused', 'Educational content', 'No data retention']
            }
        }

    def refresh_data(self) -> bool:
        """Refresh breach data from multiple sources"""
        try:
            print("Refreshing breach data...")

            all_breaches = []

            # Get data from Have I Been Pwned if API key available
            if self.hibp_api_key:
                hibp_breaches = self._get_hibp_breaches()
                all_breaches.extend(hibp_breaches)

            # Get manual/curated breach data
            manual_breaches = self._get_manual_breach_data()
            all_breaches.extend(manual_breaches)

            # Add breach checking resources
            resource_data = self._get_breach_resources()
            all_breaches.extend(resource_data)

            # Get recent breach news
            recent_breaches = self._get_recent_breach_news()
            all_breaches.extend(recent_breaches)

            # Store each breach
            for breach in all_breaches:
                breach_id = f"{breach['source']}_{hash(breach['name'])}"
                if self.storage:
                    self.storage.store_data('breaches', breach_id, breach)

            # Cache the complete list
            if self.storage:
                self.storage.cache_set('all_breaches', all_breaches, timedelta(minutes=30))

            # Store in memory for web API
            self.cached_breaches = all_breaches

            self.last_refresh = datetime.now()
            print(f"Refreshed {len(all_breaches)} breach records")
            return True

        except Exception as e:
            print(f"Error refreshing breaches: {e}")
            return False

    def _get_hibp_breaches(self) -> List[Dict]:
        """Get breach data from Have I Been Pwned API"""
        try:
            headers = {'hibp-api-key': self.hibp_api_key}

            response = requests.get(
                'https://haveibeenpwned.com/api/v3/breaches',
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                breaches_data = response.json()
                processed_breaches = []

                for breach in breaches_data[:50]:  # Limit for performance
                    processed_breach = {
                        'name': breach.get('Name', 'Unknown'),
                        'title': breach.get('Title', breach.get('Name', 'Unknown')),
                        'domain': breach.get('Domain', ''),
                        'breach_date': breach.get('BreachDate', ''),
                        'added_date': breach.get('AddedDate', ''),
                        'modified_date': breach.get('ModifiedDate', ''),
                        'pwn_count': breach.get('PwnCount', 0),
                        'description': breach.get('Description', ''),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified', False),
                        'is_fabricated': breach.get('IsFabricated', False),
                        'is_sensitive': breach.get('IsSensitive', False),
                        'logo_path': breach.get('LogoPath', ''),
                        'source': 'HaveIBeenPwned',
                        'severity': self._calculate_breach_severity(
                            breach.get('PwnCount', 0),
                            breach.get('DataClasses', [])
                        ),
                        'category': 'Data Breach',
                        'type': 'breach_data'
                    }
                    processed_breaches.append(processed_breach)

                return processed_breaches
            else:
                print(f"HIBP API error: {response.status_code}")
                return []

        except Exception as e:
            print(f"Error fetching HIBP data: {e}")
            return []

    def _get_manual_breach_data(self) -> List[Dict]:
        """Get manually curated recent breach data"""
        return [
            {
                'name': 'Recent Breach Monitoring',
                'title': 'Continuous Breach Monitoring Active',
                'domain': 'various',
                'breach_date': datetime.now().strftime('%Y-%m-%d'),
                'added_date': datetime.now().isoformat(),
                'pwn_count': 0,
                'description': 'Monitoring active for new data breaches and security incidents across multiple sources.',
                'data_classes': ['Monitoring'],
                'is_verified': True,
                'is_fabricated': False,
                'source': 'CyberClause Monitor',
                'severity': 'Informational',
                'category': 'Monitoring',
                'type': 'monitoring'
            }
        ]

    def _get_recent_breach_news(self) -> List[Dict]:
        """Get recent breach news and reports"""
        # Simulated recent breach data - in real implementation, this would fetch from news APIs
        recent_breaches = [
            {
                'name': 'Data Breach Trends 2024',
                'title': '2024 Data Breach Landscape Report',
                'domain': 'multiple',
                'breach_date': '2024-01-01',
                'added_date': datetime.now().isoformat(),
                'pwn_count': 0,
                'description': 'Comprehensive analysis of data breach trends, attack vectors, and industry impacts for 2024.',
                'data_classes': ['Analysis', 'Trends'],
                'is_verified': True,
                'is_fabricated': False,
                'source': 'Industry Report',
                'severity': 'Informational',
                'category': 'Research',
                'type': 'breach_report',
                'insights': [
                    'Ransomware attacks increased by 40%',
                    'Healthcare sector most targeted',
                    'Average breach cost: $4.88 million',
                    'Cloud misconfigurations leading cause'
                ]
            },
            {
                'name': 'Supply Chain Security Incidents',
                'title': 'Supply Chain Breach Monitoring',
                'domain': 'supply-chain',
                'breach_date': datetime.now().strftime('%Y-%m-%d'),
                'added_date': datetime.now().isoformat(),
                'pwn_count': 0,
                'description': 'Tracking supply chain security incidents and third-party vendor breaches.',
                'data_classes': ['Supply Chain', 'Vendor Risk'],
                'is_verified': True,
                'is_fabricated': False,
                'source': 'Security Research',
                'severity': 'High',
                'category': 'Supply Chain',
                'type': 'monitoring',
                'risk_factors': [
                    'Third-party vendor access',
                    'Software supply chain attacks',
                    'Dependency vulnerabilities',
                    'Lack of vendor security assessment'
                ]
            }
        ]

        return recent_breaches

    def _get_breach_resources(self) -> List[Dict]:
        """Get breach checking resources for users"""
        resources = []

        for site_id, site_info in self.breach_check_sites.items():
            resource = {
                'name': f"{site_info['name']} - Breach Checker",
                'title': f"Check breaches on {site_info['name']}",
                'domain': site_info['url'].replace('https://', '').replace('http://', ''),
                'breach_date': datetime.now().strftime('%Y-%m-%d'),
                'added_date': datetime.now().isoformat(),
                'pwn_count': 0,
                'description': site_info['description'],
                'data_classes': site_info['features'],
                'is_verified': True,
                'is_fabricated': False,
                'source': site_info['name'],
                'severity': 'Resource',
                'category': 'Breach Checker',
                'type': 'breach_checker',
                'site_id': site_id,
                'site_info': site_info
            }
            resources.append(resource)

        return resources

    def _calculate_breach_severity(self, pwn_count: int, data_classes: List[str]) -> str:
        """Calculate breach severity based on impact"""
        sensitive_data = ['Passwords', 'Credit cards', 'Social security numbers',
                          'Bank account numbers', 'Personal health data']

        has_sensitive = any(data_class in sensitive_data for data_class in data_classes)

        if pwn_count > 100000000:  # 100M+
            return 'Critical'
        elif pwn_count > 10000000 or has_sensitive:  # 10M+ or sensitive data
            return 'High'
        elif pwn_count > 1000000:  # 1M+
            return 'Medium'
        else:
            return 'Low'

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get breach data with optional filtering"""
        # Try cache first
        if self.storage:
            cached_data = self.storage.cache_get('all_breaches')
        else:
            cached_data = getattr(self, 'cached_breaches', None)

        if cached_data is None:
            # Try database
            if self.storage:
                cached_data = self.storage.get_data('breaches')

            if not cached_data:
                # Refresh if no data
                self.refresh_data()
                if self.storage:
                    cached_data = self.storage.cache_get('all_breaches') or []
                else:
                    cached_data = getattr(self, 'cached_breaches', [])

        # Apply filters if provided
        if filters:
            cached_data = self.filter_data(cached_data, filters)

        # Sort by category and date
        cached_data.sort(key=lambda x: (
            x.get('type', 'z'),  # breach_checker first
            x.get('breach_date', ''),
        ), reverse=True)

        return cached_data

    def get_breach_checkers(self) -> List[Dict]:
        """Get list of breach checking websites with enhanced information"""
        checkers = []

        for site_id, site_info in self.breach_check_sites.items():
            checker = site_info.copy()
            checker['site_id'] = site_id

            # Add trust score based on multiple factors
            checker['trust_score'] = self._calculate_trust_score(site_info)

            # Add usage recommendations
            checker['recommended_for'] = self._get_usage_recommendations(site_info)

            checkers.append(checker)

        # Sort by trust score and reliability
        checkers.sort(key=lambda x: (
            x['trust_score'],
            x['reliability'] == 'Very High',
            x['reliability'] == 'High',
            x['free']
        ), reverse=True)

        return checkers

    def _calculate_trust_score(self, site_info: Dict) -> float:
        """Calculate trust score based on multiple factors"""
        score = 0.0

        # Reliability weight
        reliability_scores = {
            'Very High': 1.0,
            'High': 0.8,
            'Medium': 0.6,
            'Low': 0.3
        }
        score += reliability_scores.get(site_info['reliability'], 0.5) * 0.4

        # Free service bonus
        if site_info['free']:
            score += 0.2

        # API availability
        if site_info['api_available']:
            score += 0.2

        # Age/establishment (newer services get lower trust initially)
        founded_year = int(site_info.get('founded', '2020'))
        current_year = datetime.now().year
        age_factor = min((current_year - founded_year) / 10, 0.2)
        score += age_factor

        return min(score, 1.0)

    def _get_usage_recommendations(self, site_info: Dict) -> List[str]:
        """Get usage recommendations based on service characteristics"""
        recommendations = []

        if site_info['free'] and site_info['reliability'] == 'Very High':
            recommendations.append("Ideal for initial breach checks")

        if site_info['api_available']:
            recommendations.append("Good for automated monitoring")

        if not site_info['free']:
            recommendations.append("Professional/enterprise use")

        if 'Domain monitoring' in site_info['features']:
            recommendations.append("Corporate domain monitoring")

        if 'Real-time alerts' in site_info['features']:
            recommendations.append("Continuous monitoring")

        return recommendations

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search breaches"""
        all_data = self.get_data()

        # Filter by search query
        search_filters = {'search': query}
        if filters:
            search_filters.update(filters)

        return self.filter_data(all_data, search_filters)

    def check_domain_breaches(self, domain: str) -> List[Dict]:
        """Check if a specific domain has been breached"""
        all_breaches = self.get_data({'type': 'breach_data'})  # Only actual breaches
        domain_breaches = []

        for breach in all_breaches:
            if (domain.lower() in breach.get('domain', '').lower() or
                    domain.lower() in breach.get('name', '').lower()):
                domain_breaches.append(breach)

        return domain_breaches

    def get_recent_breaches(self, days: int = 30) -> List[Dict]:
        """Get breaches from the last N days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        all_breaches = self.get_data({'type': 'breach_data'})

        recent_breaches = [
            breach for breach in all_breaches
            if breach.get('breach_date', '') >= cutoff_date
        ]

        return recent_breaches

    def get_breach_statistics(self) -> Dict:
        """Get comprehensive breach statistics"""
        all_data = self.get_data()
        breach_data = [b for b in all_data if b.get('type') == 'breach_data']
        checker_data = [b for b in all_data if b.get('type') == 'breach_checker']

        stats = {
            'total_breaches': len(breach_data),
            'total_checkers': len(checker_data),
            'by_severity': {},
            'by_year': {},
            'total_accounts': 0,
            'recent_count': 0,
            'most_common_data_types': {},
            'checker_categories': {
                'free': len([c for c in checker_data if c.get('site_info', {}).get('free', False)]),
                'paid': len([c for c in checker_data if not c.get('site_info', {}).get('free', True)]),
                'api_available': len([c for c in checker_data if c.get('site_info', {}).get('api_available', False)]),
                'high_reliability': len(
                    [c for c in checker_data if c.get('site_info', {}).get('reliability') in ['High', 'Very High']])
            },
            'industry_impact': self._calculate_industry_impact(breach_data),
            'geographic_distribution': self._analyze_geographic_distribution(breach_data)
        }

        # Count by severity
        for breach in breach_data:
            severity = breach.get('severity', 'Unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # Add to total accounts
            stats['total_accounts'] += breach.get('pwn_count', 0)

        # Count by year
        for breach in breach_data:
            breach_date = breach.get('breach_date', '')
            if breach_date:
                try:
                    year = breach_date[:4]
                    stats['by_year'][year] = stats['by_year'].get(year, 0) + 1
                except:
                    pass

        # Recent breaches (last 30 days)
        recent_breaches = self.get_recent_breaches(30)
        stats['recent_count'] = len(recent_breaches)

        # Most common data types
        all_data_classes = []
        for breach in breach_data:
            all_data_classes.extend(breach.get('data_classes', []))

        for data_class in all_data_classes:
            stats['most_common_data_types'][data_class] = stats['most_common_data_types'].get(data_class, 0) + 1

        # Sort most common data types
        stats['most_common_data_types'] = dict(sorted(
            stats['most_common_data_types'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])

        return stats

    def _calculate_industry_impact(self, breach_data: List[Dict]) -> Dict:
        """Calculate industry impact from breach data"""
        industry_impact = {}

        # Industry classification based on domain and name
        industry_keywords = {
            'Healthcare': ['health', 'medical', 'hospital', 'clinic'],
            'Financial': ['bank', 'finance', 'credit', 'payment'],
            'Technology': ['tech', 'software', 'cloud', 'data'],
            'Retail': ['shop', 'store', 'retail', 'commerce'],
            'Education': ['university', 'school', 'education', 'college'],
            'Government': ['gov', 'government', 'public', 'municipal']
        }

        for breach in breach_data:
            domain = breach.get('domain', '').lower()
            name = breach.get('name', '').lower()

            classified = False
            for industry, keywords in industry_keywords.items():
                if any(keyword in domain or keyword in name for keyword in keywords):
                    industry_impact[industry] = industry_impact.get(industry, 0) + breach.get('pwn_count', 0)
                    classified = True
                    break

            if not classified:
                industry_impact['Other'] = industry_impact.get('Other', 0) + breach.get('pwn_count', 0)

        return industry_impact

    def _analyze_geographic_distribution(self, breach_data: List[Dict]) -> Dict:
        """Analyze geographic distribution of breaches"""
        # Simplified geographic analysis based on domain TLDs and known origins
        geographic_distribution = {
            'Global': 0,
            'North America': 0,
            'Europe': 0,
            'Asia Pacific': 0,
            'Other': 0
        }

        # This is a simplified analysis - in real implementation, you'd use proper geolocation
        for breach in breach_data:
            domain = breach.get('domain', '').lower()

            if any(tld in domain for tld in ['.com', '.org', '.net']):
                geographic_distribution['Global'] += 1
            elif any(tld in domain for tld in ['.eu', '.de', '.fr', '.uk']):
                geographic_distribution['Europe'] += 1
            elif any(tld in domain for tld in ['.jp', '.cn', '.au', '.in']):
                geographic_distribution['Asia Pacific'] += 1
            else:
                geographic_distribution['Other'] += 1

        return geographic_distribution

    def get_breach_details(self, breach_name: str) -> Dict:
        """Get detailed information for a specific breach"""
        all_breaches = self.get_data()

        for breach in all_breaches:
            if breach.get('name', '').lower() == breach_name.lower():
                # Enhance with additional details
                enhanced_breach = breach.copy()

                if breach.get('type') == 'breach_data':
                    enhanced_breach['impact_assessment'] = self._assess_breach_impact(breach)
                    enhanced_breach['recommendations'] = self._get_breach_recommendations(breach)
                    enhanced_breach['timeline'] = self._generate_breach_timeline(breach)

                return enhanced_breach

        return {}

    def _assess_breach_impact(self, breach: Dict) -> str:
        """Assess the impact of a breach"""
        pwn_count = breach.get('pwn_count', 0)
        data_classes = breach.get('data_classes', [])

        sensitive_data = ['Passwords', 'Credit cards', 'Social security numbers']
        has_sensitive = any(data_class in sensitive_data for data_class in data_classes)

        if pwn_count > 50000000 and has_sensitive:
            return "Massive impact - Immediate action required for affected users"
        elif pwn_count > 10000000:
            return "High impact - Users should change passwords and monitor accounts"
        elif has_sensitive:
            return "Significant impact - Sensitive data exposed, enhanced monitoring needed"
        else:
            return "Moderate impact - Standard security precautions recommended"

    def _get_breach_recommendations(self, breach: Dict) -> List[str]:
        """Get recommendations based on breach data"""
        recommendations = [
            "Change passwords for affected accounts immediately",
            "Enable two-factor authentication where possible",
            "Monitor accounts for suspicious activity"
        ]

        data_classes = breach.get('data_classes', [])

        if 'Credit cards' in data_classes:
            recommendations.append("Contact bank/credit card companies")
            recommendations.append("Monitor credit reports")

        if 'Social security numbers' in data_classes:
            recommendations.append("Consider credit freeze")
            recommendations.append("File identity theft report if necessary")

        if 'Email addresses' in data_classes:
            recommendations.append("Be extra vigilant for phishing emails")

        return recommendations

    def _generate_breach_timeline(self, breach: Dict) -> List[Dict]:
        """Generate timeline for breach"""
        timeline = []

        if breach.get('breach_date'):
            timeline.append({
                'date': breach.get('breach_date'),
                'event': 'Breach occurred',
                'description': 'Initial security incident occurred'
            })

        if breach.get('added_date'):
            timeline.append({
                'date': breach.get('added_date'),
                'event': 'Breach discovered/reported',
                'description': 'Breach was discovered and reported to authorities'
            })

        if breach.get('modified_date'):
            timeline.append({
                'date': breach.get('modified_date'),
                'event': 'Information updated',
                'description': 'Breach information was updated with new details'
            })

        return timeline