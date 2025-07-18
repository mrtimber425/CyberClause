import os
from datetime import timedelta


class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cybersec-dashboard-key-2024-5tab'

    # Basic paths
    SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'settings.json')

    # API endpoints
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_ALERTS_URL = "https://www.cisa.gov/uscert/ncas/alerts.xml"
    NIST_CSF_URL = "https://www.nist.gov/cyberframework"

    # Breach detection APIs
    HIBP_API_URL = "https://haveibeenpwned.com/api/v3"

    # Enhanced RSS Feeds for comprehensive news coverage
    RSS_FEEDS = {
        # Government and official sources
        'CISA': 'https://www.cisa.gov/uscert/ncas/alerts.xml',
        'US-CERT': 'https://www.cisa.gov/uscert/ncas/current-activity.xml',
        'NIST': 'https://www.nist.gov/news-events/cybersecurity/rss.xml',
        'FBI-IC3': 'https://www.ic3.gov/Media/RSS',

        # Premium cybersecurity publications
        'KrebsOnSecurity': 'https://krebsonsecurity.com/feed/',
        'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
        'ThreatPost': 'https://threatpost.com/feed/',
        'SecurityWeek': 'https://www.securityweek.com/feed/',
        'DarkReading': 'https://www.darkreading.com/rss.xml',
        'InfoSecurity-Magazine': 'https://www.infosecurity-magazine.com/rss/news/',
        'CSO-Online': 'https://www.csoonline.com/news/index.rss',
        'SC-Magazine': 'https://www.scmagazine.com/feed',

        # Vendor intelligence feeds
        'FireEye': 'https://www.fireeye.com/blog/feed',
        'CrowdStrike': 'https://www.crowdstrike.com/blog/feed/',
        'Cisco-Talos': 'https://blog.talosintelligence.com/feeds/posts/default',
        'Microsoft-Security': 'https://www.microsoft.com/security/blog/feed/',
        'Google-Security': 'https://security.googleblog.com/feeds/posts/default',

        # Specialized sources
        'SANS-ISC': 'https://isc.sans.edu/rssfeed.xml',
        'MalwareBytes': 'https://blog.malwarebytes.com/feed/',
        'ZDNet-Security': 'https://www.zdnet.com/topic/security/rss.xml',
        'Ars-Technica-Security': 'https://feeds.arstechnica.com/arstechnica/security',

        # Threat intelligence
        'RecordedFuture': 'https://www.recordedfuture.com/feed',
        'ThreatConnect': 'https://threatconnect.com/blog/feed/',
        'Anomali': 'https://www.anomali.com/blog/rss.xml',

        # Cloud security specific
        'AWS-Security': 'https://aws.amazon.com/blogs/security/feed/',
        'Azure-Security': 'https://azure.microsoft.com/en-us/blog/topics/security/feed/',
        'Google-Cloud-Security': 'https://cloud.google.com/blog/topics/security/rss',

        # International sources
        'ENISA': 'https://www.enisa.europa.eu/news/rss',
        'NCSC-UK': 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
        'BSI-Germany': 'https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed.xml',
    }

    # 5-Tab Dashboard Configuration
    DASHBOARD_CONFIG = {
        'auto_refresh_interval': 300,  # 5 minutes
        'max_alerts_display': 10,
        'max_cves_display': 15,
        'max_news_display': 20,
        'priority_threshold': 0.6,
        'breaking_news_hours': 6,
        'critical_cve_days': 7
    }

    # CVE Search Tab Configuration
    CVE_SEARCH_CONFIG = {
        'default_limit': 50,
        'max_limit': 200,
        'cache_timeout': 300,  # 5 minutes
        'trending_days': 14,
        'recent_critical_days': 7,
        'quick_search_options': [
            {'name': 'Critical CVEs', 'params': {'severity': 'CRITICAL', 'days_back': 7}},
            {'name': 'Windows CVEs', 'params': {'query': 'windows'}},
            {'name': 'Apache CVEs', 'params': {'query': 'apache'}},
            {'name': 'Recent CVEs', 'params': {'days_back': 3}},
            {'name': 'Trending CVEs', 'params': {'days_back': 14, 'severity': 'HIGH'}}
        ]
    }

    # GRC Documents Tab Configuration
    GRC_CONFIG = {
        'document_categories': [
            'Framework', 'Standard', 'Policy', 'Guideline', 'Regulation'
        ],
        'compliance_levels': [
            'Mandatory', 'Recommended', 'Voluntary'
        ],
        'industries': [
            'All', 'Healthcare', 'Financial Services', 'Government',
            'Technology', 'Manufacturing', 'Education', 'Retail'
        ],
        'regions': [
            'Global', 'United States', 'European Union', 'Asia Pacific',
            'North America', 'Australia', 'Canada'
        ],
        'quick_search_options': [
            {'name': 'NIST', 'params': {'query': 'NIST'}},
            {'name': 'ISO', 'params': {'query': 'ISO 27001'}},
            {'name': 'GDPR', 'params': {'query': 'GDPR'}},
            {'name': 'SOX', 'params': {'query': 'SOX'}},
            {'name': 'HIPAA', 'params': {'query': 'HIPAA'}}
        ]
    }

    # Breach Checker Tab Configuration
    BREACH_CONFIG = {
        'trusted_checkers_only': True,
        'min_reliability': 'Medium',
        'show_free_services': True,
        'show_api_services': True,
        'max_checkers_display': 15
    }

    # Settings Tab Configuration
    SETTINGS_CONFIG = {
        'themes': ['blue', 'dark', 'green', 'purple'],
        'refresh_intervals': [30, 60, 300, 600, 1800],  # seconds
        'export_formats': ['json', 'csv', 'xlsx'],
        'data_retention_days': 90,
        'max_cache_size': 1000
    }

    # API rate limiting and performance
    API_CONFIG = {
        'nvd_rate_limit_delay': 6.0,  # seconds (without API key)
        'nvd_rate_limit_with_key': 0.6,  # seconds (with API key)
        'request_timeout': 30,  # seconds
        'max_retries': 3,
        'backoff_factor': 2.0
    }

    # Cache settings for different data types
    CACHE_CONFIG = {
        'cve_search_timeout': timedelta(minutes=5),
        'news_timeout': timedelta(minutes=15),
        'grc_docs_timeout': timedelta(hours=6),
        'breach_data_timeout': timedelta(minutes=30),
        'dashboard_stats_timeout': timedelta(minutes=2),
        'max_memory_cache_size': 100,
        'cleanup_interval': timedelta(hours=1)
    }

    # Security and validation settings
    SECURITY_CONFIG = {
        'validate_cve_format': True,
        'sanitize_search_queries': True,
        'max_search_query_length': 200,
        'allowed_domains': [
            'nist.gov', 'mitre.org', 'cisa.gov', 'cve.org',
            'nvd.nist.gov', 'haveibeenpwned.com'
        ],
        'csrf_enabled': True,
        'rate_limit_per_ip': 100  # requests per hour
    }

    # Logging configuration
    LOGGING_CONFIG = {
        'log_level': 'INFO',
        'log_file': 'logs/cyberclause.log',
        'max_log_size': 10485760,  # 10MB
        'backup_count': 5,
        'log_api_requests': True,
        'log_search_queries': True,
        'log_errors': True
    }

    # Dashboard display preferences
    DISPLAY_CONFIG = {
        'date_format': '%Y-%m-%d %H:%M:%S',
        'timezone': 'UTC',
        'max_description_length': 200,
        'show_source_icons': True,
        'enable_animations': True,
        'compact_mode': False
    }

    # Alert and notification settings
    ALERT_CONFIG = {
        'enable_alerts': True,
        'critical_cve_threshold': 9.0,  # CVSS score
        'high_priority_sources': [
            'CISA', 'NIST', 'Microsoft-Security', 'US-CERT'
        ],
        'alert_categories': [
            'Critical CVE', 'Major Breach', 'Zero-day', 'Government Advisory'
        ],
        'max_alerts_memory': 50
    }

    # Data source priorities and weights
    SOURCE_CONFIG = {
        'source_priorities': {
            'CISA': 1.0,
            'NIST': 0.95,
            'US-CERT': 0.9,
            'KrebsOnSecurity': 0.85,
            'BleepingComputer': 0.8,
            'Microsoft-Security': 0.8,
            'CrowdStrike': 0.75
        },
        'category_weights': {
            'Government Advisory': 1.0,
            'Vulnerabilities': 0.9,
            'Data Breaches': 0.85,
            'Threat Intelligence': 0.8,
            'Malware': 0.75
        }
    }

    # Performance optimization settings
    PERFORMANCE_CONFIG = {
        'enable_compression': True,
        'minify_responses': True,
        'use_cdn': False,
        'lazy_load_data': True,
        'batch_size': 50,
        'concurrent_requests': 5,
        'connection_pooling': True
    }

    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist"""
        directories = [
            os.path.join(os.path.dirname(__file__), 'data'),
            os.path.join(os.path.dirname(__file__), 'logs'),
            os.path.join(os.path.dirname(__file__), 'exports'),
            os.path.join(os.path.dirname(__file__), 'cache'),
            os.path.join(os.path.dirname(__file__), 'temp')
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    @classmethod
    def get_dashboard_settings(cls):
        """Get dashboard-specific settings"""
        return {
            'config': cls.DASHBOARD_CONFIG,
            'cache': cls.CACHE_CONFIG,
            'display': cls.DISPLAY_CONFIG,
            'alerts': cls.ALERT_CONFIG
        }

    @classmethod
    def get_cve_search_settings(cls):
        """Get CVE search-specific settings"""
        return {
            'config': cls.CVE_SEARCH_CONFIG,
            'api': cls.API_CONFIG,
            'cache': cls.CACHE_CONFIG,
            'security': cls.SECURITY_CONFIG
        }

    @classmethod
    def get_grc_settings(cls):
        """Get GRC documents-specific settings"""
        return {
            'config': cls.GRC_CONFIG,
            'cache': cls.CACHE_CONFIG,
            'display': cls.DISPLAY_CONFIG
        }

    @classmethod
    def get_breach_settings(cls):
        """Get breach checker-specific settings"""
        return {
            'config': cls.BREACH_CONFIG,
            'cache': cls.CACHE_CONFIG,
            'security': cls.SECURITY_CONFIG
        }

    @classmethod
    def get_settings_config(cls):
        """Get settings tab configuration"""
        return {
            'config': cls.SETTINGS_CONFIG,
            'themes': cls.SETTINGS_CONFIG['themes'],
            'intervals': cls.SETTINGS_CONFIG['refresh_intervals'],
            'formats': cls.SETTINGS_CONFIG['export_formats']
        }

    @classmethod
    def get_api_settings(cls):
        """Get API-specific settings"""
        return {
            'nvd_api_url': cls.NVD_API_URL,
            'hibp_api_url': cls.HIBP_API_URL,
            'rate_limits': cls.API_CONFIG,
            'timeouts': cls.API_CONFIG,
            'security': cls.SECURITY_CONFIG
        }

    @classmethod
    def get_news_settings(cls):
        """Get news feed settings"""
        return {
            'rss_feeds': cls.RSS_FEEDS,
            'source_config': cls.SOURCE_CONFIG,
            'cache_config': cls.CACHE_CONFIG,
            'alert_config': cls.ALERT_CONFIG
        }

    @classmethod
    def get_performance_settings(cls):
        """Get performance optimization settings"""
        return {
            'performance': cls.PERFORMANCE_CONFIG,
            'cache': cls.CACHE_CONFIG,
            'api': cls.API_CONFIG,
            'logging': cls.LOGGING_CONFIG
        }

    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        errors = []

        # Validate required directories
        try:
            cls.ensure_directories()
        except Exception as e:
            errors.append(f"Directory creation failed: {e}")

        # Validate API URLs
        required_urls = [cls.NVD_API_URL, cls.HIBP_API_URL]
        for url in required_urls:
            if not url or not url.startswith('http'):
                errors.append(f"Invalid API URL: {url}")

        # Validate RSS feeds
        if not cls.RSS_FEEDS or len(cls.RSS_FEEDS) == 0:
            errors.append("No RSS feeds configured")

        # Validate cache timeouts
        for key, value in cls.CACHE_CONFIG.items():
            if 'timeout' in key and not isinstance(value, timedelta):
                errors.append(f"Invalid cache timeout: {key}")

        return errors

    @classmethod
    def get_feature_flags(cls):
        """Get feature flags for different components"""
        return {
            'live_search': True,
            'auto_refresh': True,
            'caching': True,
            'api_validation': True,
            'threat_intelligence': True,
            'breach_monitoring': True,
            'grc_documents': True,
            'export_functionality': True,
            'advanced_filtering': True,
            'real_time_alerts': True
        }

    @classmethod
    def get_tab_configurations(cls):
        """Get configurations for all 5 tabs"""
        return {
            'dashboard': {
                'name': 'Dashboard',
                'icon': '📊',
                'refresh_interval': cls.DASHBOARD_CONFIG['auto_refresh_interval'],
                'auto_refresh': True,
                'priority_data': True
            },
            'cve': {
                'name': 'CVE Search',
                'icon': '🔍',
                'live_search': True,
                'cache_results': True,
                'advanced_filters': True
            },
            'grc': {
                'name': 'GRC Documents',
                'icon': '📚',
                'document_types': cls.GRC_CONFIG['document_categories'],
                'compliance_tracking': True,
                'search_enabled': True
            },
            'breach': {
                'name': 'Breach Checker',
                'icon': '🔓',
                'trusted_sources': True,
                'educational_content': True,
                'external_links': True
            },
            'settings': {
                'name': 'Settings',
                'icon': '⚙️',
                'theme_options': cls.SETTINGS_CONFIG['themes'],
                'api_management': True,
                'export_options': True
            }
        }