from .base_engine import BaseEngine
from api_clients.rss_client import RSSClient
from config import Config
from typing import List, Dict
from datetime import datetime, timedelta
import requests
import re
from urllib.parse import urljoin, urlparse
import threading


class NewsEngine(BaseEngine):
    def __init__(self, storage, api_manager):
        super().__init__(storage, api_manager)
        self.refresh_interval = timedelta(minutes=15)
        self.rss_client = RSSClient(Config.RSS_FEEDS)
        self._last_successful_refresh = None

    def refresh_data(self) -> bool:
        """Refresh news data with improved error handling"""
        try:
            print("Refreshing cybersecurity news data...")

            # First try to get cached data to avoid complete failure
            if self.storage:
                cached_articles = self.storage.cache_get('all_news') or []
            else:
                cached_articles = getattr(self, 'cached_news', [])

            # Fetch news from RSS feeds with error handling
            try:
                articles = self.rss_client.fetch_news(max_articles_per_feed=30)
            except Exception as e:
                print(f"RSS fetch failed: {e}")
                # Use fallback method
                articles = self._fetch_fallback_news()

            if not articles and cached_articles:
                print("Using cached articles due to fetch failure")
                return True

            # Enhanced article processing
            processed_articles = []
            for article in articles:
                try:
                    enhanced_article = self._enhance_article(article)
                    if enhanced_article:
                        processed_articles.append(enhanced_article)
                except Exception as e:
                    print(f"Error processing article: {e}")
                    # Keep original article if enhancement fails
                    processed_articles.append(article)

            if not processed_articles:
                print("No articles processed, keeping existing data")
                return len(cached_articles) > 0

            # Store each article
            for article in processed_articles:
                try:
                    article_id = f"{article['source']}_{hash(article['title'])}"
                    if self.storage:
                        self.storage.store_data('news', article_id, article)
                except Exception as e:
                    print(f"Error storing article: {e}")
                    continue

            # Cache the complete list
            if self.storage:
                self.storage.cache_set('all_news', processed_articles, timedelta(minutes=15))

            # Store in memory for web API
            self.cached_news = processed_articles

            self.last_refresh = datetime.now()
            self._last_successful_refresh = self.last_refresh
            print(f"Refreshed {len(processed_articles)} news articles")
            return True

        except Exception as e:
            print(f"Error refreshing news: {e}")
            # Return True if we have cached data
            if self.storage:
                cached_data = self.storage.cache_get('all_news')
            else:
                cached_data = getattr(self, 'cached_news', [])
            return cached_data is not None and len(cached_data) > 0

    def _fetch_fallback_news(self) -> List[Dict]:
        """Fallback method to fetch news when RSS fails"""
        print("Using fallback news sources...")

        # Simplified RSS feeds that are more reliable
        fallback_feeds = {
            'CISA': 'https://www.cisa.gov/uscert/ncas/alerts.xml',
            'KrebsOnSecurity': 'https://krebsonsecurity.com/feed/',
            'BleepingComputer': 'https://www.bleepingcomputer.com/feed/'
        }

        articles = []
        for source, url in fallback_feeds.items():
            try:
                # Simple request with timeout
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    # Basic article creation
                    articles.append({
                        'title': f'Latest from {source}',
                        'description': f'Security updates from {source}',
                        'url': url.replace('/feed/', '/').replace('.xml', ''),
                        'published': datetime.now().isoformat(),
                        'source': source,
                        'category': 'General Security',
                        'threat_level': 'Informational',
                        'relevance_score': 0.5
                    })
            except:
                continue

        return articles

    def _enhance_article(self, article: Dict) -> Dict:
        """Enhanced article processing with error handling"""
        try:
            enhanced = article.copy()

            # Safe URL validation
            enhanced['url'] = self._validate_url_safe(article.get('url', ''))

            # Enhanced categorization
            enhanced['category'] = self._categorize_article_enhanced(
                article.get('title', ''),
                article.get('description', ''),
                article.get('source', '')
            )

            # Add threat level
            enhanced['threat_level'] = self._assess_threat_level(
                article.get('title', ''),
                article.get('description', '')
            )

            # Add relevance score
            enhanced['relevance_score'] = self._calculate_relevance(enhanced)

            # Extract key entities
            enhanced['entities'] = self._extract_entities_safe(
                article.get('title', '') + ' ' + article.get('description', '')
            )

            # Add reading time estimate
            enhanced['reading_time'] = self._estimate_reading_time(
                article.get('description', '')
            )

            # Add priority score for dashboard display
            enhanced['priority_score'] = self._calculate_priority_score(enhanced)

            # Add action items based on content
            enhanced['action_items'] = self._generate_action_items(enhanced)

            # Add impact assessment
            enhanced['impact_level'] = self._assess_impact_level(enhanced)

            return enhanced

        except Exception as e:
            print(f"Error enhancing article: {e}")
            # Return original with basic enhancements
            article['category'] = article.get('category', 'General Security')
            article['threat_level'] = article.get('threat_level', 'Informational')
            article['relevance_score'] = article.get('relevance_score', 0.5)
            article['entities'] = article.get('entities', [])
            article['reading_time'] = article.get('reading_time', 2)
            article['priority_score'] = 0.5
            article['action_items'] = []
            article['impact_level'] = 'Low'
            return article

    def _validate_url_safe(self, url: str) -> str:
        """Safe URL validation without external requests"""
        if not url:
            return ''

        try:
            # Basic URL cleaning
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            # Basic validation without external request
            parsed = urlparse(url)
            if parsed.netloc and parsed.scheme:
                return url

        except:
            pass

        return url

    def _extract_entities_safe(self, text: str) -> List[str]:
        """Safe entity extraction with error handling"""
        try:
            entities = []

            if not text:
                return entities

            # CVE patterns
            try:
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, text, re.IGNORECASE)
                entities.extend(cves[:5])  # Limit to 5
            except:
                pass

            # Common company names
            companies = [
                'Microsoft', 'Google', 'Apple', 'Amazon', 'Meta',
                'Tesla', 'SolarWinds', 'Cisco', 'VMware', 'Adobe',
                'Oracle', 'IBM', 'SAP', 'Salesforce', 'Netflix'
            ]

            try:
                text_lower = text.lower()
                for company in companies:
                    if company.lower() in text_lower and company not in entities:
                        entities.append(company)
                        if len(entities) >= 8:  # Limit total entities
                            break
            except:
                pass

            # Threat actor groups
            threat_actors = [
                'APT1', 'APT28', 'APT29', 'Lazarus', 'Carbanak',
                'FIN7', 'Cobalt', 'DarkHalo', 'HAFNIUM', 'Nobelium'
            ]

            try:
                for actor in threat_actors:
                    if actor.lower() in text_lower and actor not in entities:
                        entities.append(actor)
                        if len(entities) >= 10:
                            break
            except:
                pass

            return entities

        except Exception as e:
            print(f"Error extracting entities: {e}")
            return []

    def _categorize_article_enhanced(self, title: str, description: str, source: str) -> str:
        """Enhanced categorization with error handling"""
        try:
            text = (title + ' ' + description).lower()

            # Government sources
            if source.lower() in ['cisa', 'us-cert', 'nist', 'fbi', 'nsa']:
                return 'Government Advisory'

            # Vulnerability keywords
            if any(keyword in text for keyword in ['cve-', 'vulnerability', 'exploit', 'zero-day', 'patch']):
                return 'Vulnerabilities'

            # Breach keywords
            if any(keyword in text for keyword in ['breach', 'leaked', 'exposed', 'stolen', 'hack']):
                return 'Data Breaches'

            # Malware keywords
            if any(keyword in text for keyword in ['malware', 'ransomware', 'trojan', 'virus', 'backdoor']):
                return 'Malware'

            # Threat intelligence
            if any(keyword in text for keyword in ['apt', 'threat actor', 'campaign', 'attribution']):
                return 'Threat Intelligence'

            # Cloud security
            if any(keyword in text for keyword in ['cloud', 'aws', 'azure', 'gcp', 'saas']):
                return 'Cloud Security'

            # Cryptocurrency/Blockchain
            if any(keyword in text for keyword in ['crypto', 'bitcoin', 'blockchain', 'defi', 'nft']):
                return 'Cryptocurrency'

            # IoT/Industrial
            if any(keyword in text for keyword in ['iot', 'industrial', 'scada', 'ics', 'smart']):
                return 'IoT/Industrial'

            # Mobile security
            if any(keyword in text for keyword in ['mobile', 'android', 'ios', 'smartphone']):
                return 'Mobile Security'

            return 'General Security'

        except Exception as e:
            print(f"Error categorizing article: {e}")
            return 'General Security'

    def _assess_threat_level(self, title: str, description: str) -> str:
        """Enhanced threat level assessment"""
        try:
            text = (title + ' ' + description).lower()

            # Critical threats
            if any(keyword in text for keyword in ['critical', 'zero-day', 'active exploitation', 'emergency']):
                return 'Critical'

            # High threats
            elif any(keyword in text for keyword in ['high', 'severe', 'major breach', 'nation-state']):
                return 'High'

            # Medium threats
            elif any(keyword in text for keyword in ['vulnerability', 'patch', 'security update', 'incident']):
                return 'Medium'

            # Low threats
            elif any(keyword in text for keyword in ['advisory', 'recommendation', 'guidance']):
                return 'Low'

            return 'Informational'

        except:
            return 'Informational'

    def _calculate_relevance(self, article: Dict) -> float:
        """Enhanced relevance calculation"""
        try:
            score = 0.5  # Base score

            # Source credibility boost
            credible_sources = ['cisa', 'krebs', 'bleeping', 'threat', 'security', 'cert']
            source = article.get('source', '').lower()

            if any(cred in source for cred in credible_sources):
                score += 0.2

            # Category relevance
            high_relevance = ['Vulnerabilities', 'Data Breaches', 'Threat Intelligence', 'Government Advisory']
            if article.get('category') in high_relevance:
                score += 0.2

            # Threat level impact
            threat_level = article.get('threat_level', '')
            if threat_level == 'Critical':
                score += 0.3
            elif threat_level == 'High':
                score += 0.2
            elif threat_level == 'Medium':
                score += 0.1

            # Recency boost
            published = article.get('published', '')
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    hours_old = (datetime.now() - pub_date.replace(tzinfo=None)).total_seconds() / 3600
                    if hours_old < 24:  # Less than 24 hours old
                        score += 0.15
                    elif hours_old < 72:  # Less than 3 days old
                        score += 0.1
                except:
                    pass

            return min(score, 1.0)

        except:
            return 0.5

    def _calculate_priority_score(self, article: Dict) -> float:
        """Calculate priority score for dashboard display"""
        try:
            priority = 0.5

            # Threat level weight
            threat_weights = {
                'Critical': 1.0,
                'High': 0.8,
                'Medium': 0.6,
                'Low': 0.4,
                'Informational': 0.2
            }
            priority += threat_weights.get(article.get('threat_level', 'Informational'), 0.2) * 0.4

            # Category weight
            category_weights = {
                'Government Advisory': 0.9,
                'Vulnerabilities': 0.8,
                'Data Breaches': 0.8,
                'Threat Intelligence': 0.7,
                'Malware': 0.7,
                'Cloud Security': 0.6
            }
            priority += category_weights.get(article.get('category', 'General Security'), 0.5) * 0.3

            # Relevance score weight
            priority += article.get('relevance_score', 0.5) * 0.3

            return min(priority, 1.0)

        except:
            return 0.5

    def _generate_action_items(self, article: Dict) -> List[str]:
        """Generate action items based on article content"""
        try:
            actions = []
            text = (article.get('title', '') + ' ' + article.get('description', '')).lower()
            category = article.get('category', '')
            threat_level = article.get('threat_level', '')

            if 'vulnerabilities' in category.lower() or 'cve-' in text:
                actions.append("Check for affected systems in your environment")
                actions.append("Review vendor security advisories")
                if threat_level in ['Critical', 'High']:
                    actions.append("Apply patches immediately")

            if 'breach' in text or 'Data Breaches' in category:
                actions.append("Check if your organization is affected")
                actions.append("Review third-party vendor security")
                actions.append("Monitor for credential exposure")

            if 'malware' in text or 'ransomware' in text:
                actions.append("Update antivirus signatures")
                actions.append("Review backup procedures")
                actions.append("Conduct security awareness training")

            if 'threat' in text or 'apt' in text:
                actions.append("Review threat intelligence feeds")
                actions.append("Update detection rules")
                actions.append("Assess threat actor TTPs")

            if not actions:
                actions.append("Monitor for further developments")
                actions.append("Review security posture")

            return actions[:4]  # Limit to 4 actions

        except:
            return ["Monitor security alerts"]

    def _assess_impact_level(self, article: Dict) -> str:
        """Assess potential impact level"""
        try:
            threat_level = article.get('threat_level', 'Informational')
            category = article.get('category', '')

            if threat_level == 'Critical':
                return 'Critical'
            elif threat_level == 'High' and category in ['Vulnerabilities', 'Data Breaches']:
                return 'High'
            elif threat_level in ['High', 'Medium']:
                return 'Medium'
            else:
                return 'Low'

        except:
            return 'Low'

    def _estimate_reading_time(self, description: str) -> int:
        """Safe reading time estimation"""
        try:
            if not description:
                return 1
            word_count = len(description.split())
            return max(1, round(word_count / 225))
        except:
            return 2

    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get news data with performance optimization"""
        # Try cache first for speed
        if self.storage:
            cached_data = self.storage.cache_get('all_news')
        else:
            cached_data = getattr(self, 'cached_news', None)

        if cached_data is None:
            # Try to get from database
            if self.storage:
                cached_data = self.storage.get_data('news')

            if not cached_data:
                # Last resort: try refresh
                print("No cached news data, attempting refresh...")
                success = self.refresh_data()
                if success:
                    if self.storage:
                        cached_data = self.storage.cache_get('all_news') or []
                    else:
                        cached_data = getattr(self, 'cached_news', [])
                else:
                    # Return empty list with message
                    return [{
                        'title': 'News Service Temporarily Unavailable',
                        'description': 'Unable to fetch latest news. Please try refreshing or check your internet connection.',
                        'url': '#',
                        'published': datetime.now().isoformat(),
                        'source': 'System',
                        'category': 'System Message',
                        'threat_level': 'Informational',
                        'relevance_score': 0.0,
                        'entities': [],
                        'reading_time': 1,
                        'priority_score': 0.0,
                        'action_items': ['Check internet connection'],
                        'impact_level': 'Low'
                    }]

        # Apply filters if provided
        if filters and cached_data:
            try:
                cached_data = self.filter_data(cached_data, filters)
            except Exception as e:
                print(f"Error applying filters: {e}")

        # Sort by priority score and date
        try:
            cached_data.sort(
                key=lambda x: (x.get('priority_score', 0), x.get('published', '')),
                reverse=True
            )
        except Exception as e:
            print(f"Error sorting data: {e}")

        return cached_data[:100]  # Limit for performance

    def get_high_priority_news(self, limit: int = 20) -> List[Dict]:
        """Get high-priority news for dashboard display"""
        all_news = self.get_data()

        # Filter for high-priority news
        high_priority = [
            article for article in all_news
            if article.get('priority_score', 0) >= 0.6 or
               article.get('threat_level') in ['Critical', 'High']
        ]

        return high_priority[:limit]

    def get_breaking_news(self, hours: int = 24) -> List[Dict]:
        """Get breaking news from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        all_news = self.get_data()

        breaking_news = []
        for article in all_news:
            try:
                published = datetime.fromisoformat(article.get('published', '').replace('Z', '+00:00'))
                if published.replace(tzinfo=None) > cutoff_time:
                    breaking_news.append(article)
            except:
                continue

        # Sort by priority and recency
        breaking_news.sort(
            key=lambda x: (x.get('priority_score', 0), x.get('published', '')),
            reverse=True
        )

        return breaking_news[:10]

    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search news articles with error handling"""
        try:
            all_data = self.get_data()

            if not query:
                return all_data

            # Filter by search query
            search_filters = {'search': query}
            if filters:
                search_filters.update(filters)

            return self.filter_data(all_data, search_filters)

        except Exception as e:
            print(f"Error searching news: {e}")
            return []

    def get_news_statistics(self) -> Dict:
        """Get comprehensive news statistics"""
        try:
            all_data = self.get_data()

            if not all_data:
                return {
                    'total_articles': 0,
                    'by_category': {},
                    'by_threat_level': {},
                    'by_source': {},
                    'recent_count': 0,
                    'avg_relevance': 0,
                    'trending_topics': [],
                    'high_priority_count': 0,
                    'breaking_news_count': 0
                }

            stats = {
                'total_articles': len(all_data),
                'by_category': {},
                'by_threat_level': {},
                'by_source': {},
                'by_impact_level': {},
                'recent_count': 0,
                'avg_relevance': 0,
                'avg_priority': 0,
                'trending_topics': [],
                'high_priority_count': 0,
                'breaking_news_count': 0,
                'most_active_sources': {},
                'threat_timeline': {}
            }

            relevance_scores = []
            priority_scores = []

            for article in all_data:
                # Safe category counting
                category = article.get('category', 'Unknown')
                stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

                # Safe threat level counting
                threat_level = article.get('threat_level', 'Unknown')
                stats['by_threat_level'][threat_level] = stats['by_threat_level'].get(threat_level, 0) + 1

                # Safe source counting
                source = article.get('source', 'Unknown')
                stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

                # Impact level counting
                impact_level = article.get('impact_level', 'Low')
                stats['by_impact_level'][impact_level] = stats['by_impact_level'].get(impact_level, 0) + 1

                # Safe relevance scoring
                relevance = article.get('relevance_score', 0)
                if isinstance(relevance, (int, float)):
                    relevance_scores.append(relevance)

                # Priority scoring
                priority = article.get('priority_score', 0)
                if isinstance(priority, (int, float)):
                    priority_scores.append(priority)

                # High priority count
                if priority >= 0.6:
                    stats['high_priority_count'] += 1

            # Recent count (last 24 hours)
            try:
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                stats['recent_count'] = len([
                    a for a in all_data
                    if a.get('published', '') >= cutoff
                ])
            except:
                stats['recent_count'] = 0

            # Breaking news count (last 6 hours)
            try:
                breaking_cutoff = (datetime.now() - timedelta(hours=6)).isoformat()
                stats['breaking_news_count'] = len([
                    a for a in all_data
                    if a.get('published', '') >= breaking_cutoff and a.get('priority_score', 0) >= 0.7
                ])
            except:
                stats['breaking_news_count'] = 0

            # Average scores
            if relevance_scores:
                stats['avg_relevance'] = sum(relevance_scores) / len(relevance_scores)

            if priority_scores:
                stats['avg_priority'] = sum(priority_scores) / len(priority_scores)

            # Most active sources (top 5)
            stats['most_active_sources'] = dict(sorted(
                stats['by_source'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])

            return stats

        except Exception as e:
            print(f"Error getting news statistics: {e}")
            return {
                'total_articles': 0,
                'by_category': {},
                'by_threat_level': {},
                'by_source': {},
                'recent_count': 0,
                'avg_relevance': 0,
                'trending_topics': [],
                'error': str(e)
            }