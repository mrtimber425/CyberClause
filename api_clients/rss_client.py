import feedparser
import requests
from datetime import datetime, timedelta
from typing import List, Dict
import re
from urllib.parse import urljoin, urlparse
import time
import concurrent.futures
import threading


class RSSClient:
    def __init__(self, rss_feeds: Dict[str, str]):
        self.rss_feeds = rss_feeds
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberClause-Dashboard/3.1 (cybersecurity-news-aggregator)',
            'Accept': 'application/rss+xml, application/xml, text/xml'
        })
        # Set connection pool settings for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=1
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def fetch_news(self, max_articles_per_feed: int = 30) -> List[Dict]:
        """Fetch news with improved performance and error handling"""
        all_articles = []
        successful_feeds = 0

        # Use ThreadPoolExecutor for concurrent fetching
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all feed fetch tasks
            future_to_source = {
                executor.submit(self._fetch_from_feed_safe, source_name, feed_url, max_articles_per_feed): source_name
                for source_name, feed_url in self.rss_feeds.items()
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_source, timeout=30):
                source_name = future_to_source[future]
                try:
                    articles = future.result(timeout=10)
                    if articles:
                        all_articles.extend(articles)
                        successful_feeds += 1
                        print(f"✅ {source_name}: {len(articles)} articles")
                    else:
                        print(f"⚠️ {source_name}: No articles retrieved")
                except Exception as e:
                    print(f"❌ {source_name}: Failed - {str(e)[:50]}")
                    continue

        print(f"📰 Fetched from {successful_feeds}/{len(self.rss_feeds)} feeds")

        # If we got very few articles, add some fallback content
        if len(all_articles) < 5:
            all_articles.extend(self._get_fallback_articles())

        # Remove duplicates and sort
        unique_articles = self._remove_duplicates_fast(all_articles)
        unique_articles.sort(key=lambda x: x.get('published', ''), reverse=True)

        return unique_articles[:100]  # Limit for performance

    def _fetch_from_feed_safe(self, source_name: str, feed_url: str, max_articles: int) -> List[Dict]:
        """Safely fetch from a single RSS feed with timeout and error handling"""
        try:
            # Quick connection test first
            response = self.session.head(feed_url, timeout=5)
            if response.status_code not in [200, 301, 302]:
                return []

            # Parse RSS feed with timeout
            feed_data = feedparser.parse(feed_url)

            if feed_data.bozo and feed_data.bozo_exception:
                print(f"Feed parsing warning for {source_name}: {feed_data.bozo_exception}")

            if not hasattr(feed_data, 'entries') or not feed_data.entries:
                return []

            articles = []
            for entry in feed_data.entries[:max_articles]:
                try:
                    article = self._process_entry_fast(entry, source_name)
                    if article:
                        articles.append(article)
                except Exception as e:
                    # Skip problematic entries
                    continue

            return articles

        except Exception as e:
            return []

    def _process_entry_fast(self, entry, source_name: str) -> Dict:
        """Fast processing of RSS entry with minimal validation"""
        # Extract basic information with fallbacks
        title = getattr(entry, 'title', 'No Title')[:200]  # Limit length

        # Get description from multiple possible fields
        description = ''
        for field in ['summary', 'description', 'content']:
            if hasattr(entry, field):
                content = getattr(entry, field)
                if isinstance(content, list) and content:
                    description = content[0].get('value', '') if isinstance(content[0], dict) else str(content[0])
                else:
                    description = str(content)
                break

        # Clean and limit description
        description = self._clean_text_fast(description)[:500]

        # Extract URL
        url = getattr(entry, 'link', '') or getattr(entry, 'id', '')

        # Parse date
        published = self._parse_date_fast(getattr(entry, 'published', ''))

        # Basic categorization
        category = self._categorize_fast(title, description, source_name)

        return {
            'title': title,
            'description': description,
            'url': url,
            'published': published,
            'source': source_name,
            'category': category,
            'threat_level': self._assess_threat_fast(title + ' ' + description),
            'relevance_score': self._calculate_relevance_fast(source_name, category),
            'reading_time': max(1, len(description.split()) // 200),
            'entities': self._extract_entities_fast(title + ' ' + description)
        }

    def _clean_text_fast(self, text: str) -> str:
        """Fast text cleaning"""
        if not text:
            return ''

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', str(text))
        # Remove extra whitespace
        text = ' '.join(text.split())

        return text.strip()

    def _parse_date_fast(self, date_str: str) -> str:
        """Fast date parsing with fallback"""
        if not date_str:
            return datetime.now().isoformat()

        try:
            # Try feedparser's built-in parser first
            parsed_time = getattr(feedparser, '_parse_date', lambda x: None)(date_str)
            if parsed_time:
                return datetime(*parsed_time[:6]).isoformat()
        except:
            pass

        # Fallback to current time
        return datetime.now().isoformat()

    def _categorize_fast(self, title: str, description: str, source: str) -> str:
        """Fast categorization using keyword matching"""
        text = (title + ' ' + description).lower()

        # Quick keyword-based categorization
        if any(word in text for word in ['cve-', 'vulnerability', 'exploit', 'patch']):
            return 'Vulnerabilities'
        elif any(word in text for word in ['breach', 'leaked', 'exposed', 'hack']):
            return 'Data Breaches'
        elif any(word in text for word in ['malware', 'ransomware', 'trojan']):
            return 'Malware'
        elif any(word in text for word in ['apt', 'threat', 'campaign']):
            return 'Threat Intelligence'
        elif source.lower() in ['cisa', 'us-cert', 'nist']:
            return 'Government Advisory'
        else:
            return 'General Security'

    def _assess_threat_fast(self, text: str) -> str:
        """Fast threat level assessment"""
        text_lower = text.lower()

        if any(word in text_lower for word in ['critical', 'zero-day', 'active']):
            return 'Critical'
        elif any(word in text_lower for word in ['high', 'severe', 'major']):
            return 'High'
        elif any(word in text_lower for word in ['vulnerability', 'patch']):
            return 'Medium'
        else:
            return 'Low'

    def _calculate_relevance_fast(self, source: str, category: str) -> float:
        """Fast relevance calculation"""
        score = 0.5

        # Source credibility boost
        credible_sources = ['cisa', 'krebs', 'bleeping', 'threat']
        if any(cred in source.lower() for cred in credible_sources):
            score += 0.3

        # Category relevance
        high_relevance = ['Vulnerabilities', 'Data Breaches', 'Threat Intelligence']
        if category in high_relevance:
            score += 0.2

        return min(score, 1.0)

    def _extract_entities_fast(self, text: str) -> List[str]:
        """Fast entity extraction"""
        entities = []

        if not text:
            return entities

        try:
            # CVE patterns
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
            entities.extend(cves[:3])  # Limit to 3

            # Common company names
            companies = ['Microsoft', 'Google', 'Apple', 'Amazon', 'Cisco']
            text_lower = text.lower()

            for company in companies:
                if company.lower() in text_lower and len(entities) < 5:
                    entities.append(company)
        except:
            pass

        return entities

    def _remove_duplicates_fast(self, articles: List[Dict]) -> List[Dict]:
        """Fast duplicate removal using title comparison"""
        seen_titles = set()
        unique_articles = []

        for article in articles:
            # Normalize title for comparison
            title_key = re.sub(r'[^\w\s]', '', article.get('title', '').lower())
            title_key = ' '.join(title_key.split())[:50]  # First 50 chars

            if title_key not in seen_titles and len(title_key) > 10:
                seen_titles.add(title_key)
                unique_articles.append(article)

        return unique_articles

    def _get_fallback_articles(self) -> List[Dict]:
        """Generate fallback articles when feeds fail"""
        return [
            {
                'title': 'CyberClause Dashboard - News Service Status',
                'description': 'The news aggregation service is currently experiencing connectivity issues with some RSS feeds. This is usually temporary and resolves automatically.',
                'url': '#',
                'published': datetime.now().isoformat(),
                'source': 'System',
                'category': 'System Status',
                'threat_level': 'Informational',
                'relevance_score': 0.1,
                'reading_time': 1,
                'entities': []
            },
            {
                'title': 'Security Best Practices Reminder',
                'description': 'While waiting for the latest news, remember to keep your systems updated, use strong passwords, enable 2FA, and stay vigilant against phishing attempts.',
                'url': '#',
                'published': datetime.now().isoformat(),
                'source': 'CyberClause',
                'category': 'Best Practices',
                'threat_level': 'Informational',
                'relevance_score': 0.3,
                'reading_time': 1,
                'entities': []
            }
        ]

    def validate_feeds_fast(self) -> Dict[str, bool]:
        """Quick validation of RSS feeds"""
        results = {}

        def check_feed(source_name, feed_url):
            try:
                response = self.session.head(feed_url, timeout=3)
                results[source_name] = response.status_code in [200, 301, 302]
            except:
                results[source_name] = False

        # Use threading for concurrent validation
        threads = []
        for source_name, feed_url in list(self.rss_feeds.items())[:5]:  # Limit to 5 for speed
            thread = threading.Thread(target=check_feed, args=(source_name, feed_url))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=5)

        return results