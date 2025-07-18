from flask import Flask, render_template_string, jsonify, request
import webbrowser
import threading
import time
from datetime import datetime
import os
import json

# Import our custom modules
from config import Config
from utils.api_manager import APIKeyManager
from engines.vulnerabilities_engine import VulnerabilitiesEngine
from engines.news_engine import NewsEngine
from engines.cyber_docs_engine import CyberDocsEngine
from engines.breaches_engine import BreachesEngine

try:
    from utils.enhanced_api_status import APIStatusManager

    ENHANCED_API_STATUS = True
except ImportError:
    ENHANCED_API_STATUS = False


# Fallback API status manager
class BasicAPIStatusManager:
    def __init__(self, api_manager):
        self.api_manager = api_manager

    def get_api_status(self, service):
        api_key = self.api_manager.get_api_key(service)
        if not api_key:
            return {'status': 'no_key', 'message': 'No API key configured', 'indicator': '⚪ Not Configured',
                    'color': '#999999'}
        else:
            return {'status': 'configured', 'message': 'API key configured', 'indicator': '🔑 Configured',
                    'color': '#2196f3'}


app = Flask(__name__)
app.config.from_object(Config)

# Initialize components
print("Initializing CyberClause Dashboard - 6-Tab Mode...")
api_manager = APIKeyManager(Config.SETTINGS_FILE)

# Initialize engines
engines = {
    'vulnerabilities': VulnerabilitiesEngine(None, api_manager),
    'news': NewsEngine(None, api_manager),
    'cyber_docs': CyberDocsEngine(None, api_manager),
    'breaches': BreachesEngine(None, api_manager)
}

# Initialize API status manager
if ENHANCED_API_STATUS:
    api_status_manager = APIStatusManager(api_manager)
else:
    api_status_manager = BasicAPIStatusManager(api_manager)

# Enhanced HTML template with 6 tabs including News
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberClause Dashboard v3.1 - 6-Tab Operations Center</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: #333; height: 100vh; overflow: hidden; }
        .container { display: grid; grid-template-columns: 250px 1fr; grid-template-rows: 70px 1fr; height: 100vh; background: #fff; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { grid-column: 1 / -1; background: linear-gradient(90deg, #1a237e 0%, #3949ab 100%); color: white; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 1.6em; font-weight: 600; }
        .header-actions { display: flex; gap: 10px; align-items: center; }
        .status-indicator { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; background: #4caf50; color: white; }
        .sidebar { background: #f8f9fa; border-right: 1px solid #e0e0e0; overflow-y: auto; }
        .nav-item { display: block; padding: 15px 18px; color: #555; text-decoration: none; border-bottom: 1px solid #e0e0e0; transition: all 0.3s ease; cursor: pointer; font-size: 0.95em; }
        .nav-item:hover { background: #e3f2fd; color: #1976d2; transform: translateX(5px); }
        .nav-item.active { background: #1976d2; color: white; border-left: 4px solid #0d47a1; }
        .nav-item i { margin-right: 12px; width: 20px; font-size: 1.1em; }
        .main-content { padding: 25px; overflow-y: auto; background: #fafafa; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .content-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 2px solid #e0e0e0; }
        .content-header h2 { color: #1976d2; font-size: 1.8em; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9em; transition: all 0.3s ease; text-decoration: none; display: inline-block; }
        .btn-primary { background: #1976d2; color: white; }
        .btn-primary:hover { background: #1565c0; transform: translateY(-2px); }
        .btn-secondary { background: #4caf50; color: white; }
        .btn-secondary:hover { background: #45a049; transform: translateY(-2px); }
        .btn-warning { background: #ff9800; color: white; }
        .btn-warning:hover { background: #f57c00; transform: translateY(-2px); }
        .card { background: white; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; overflow: hidden; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        .card-header { padding: 15px 20px; background: linear-gradient(90deg, #f5f5f5 0%, #e8e8e8 100%); border-bottom: 1px solid #e0e0e0; font-weight: 600; color: #333; }
        .card-body { padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
        .search-container { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; border-left: 4px solid #1976d2; }
        .search-row { display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 15px; align-items: end; margin-bottom: 15px; }
        .search-group { display: flex; flex-direction: column; }
        .search-group label { font-weight: 600; color: #555; margin-bottom: 5px; font-size: 0.9em; }
        .search-input, .search-select { padding: 12px; border: 2px solid #e0e0e0; border-radius: 6px; font-size: 1em; transition: border-color 0.3s ease; }
        .search-input:focus, .search-select:focus { outline: none; border-color: #1976d2; }
        .search-btn { padding: 12px 24px; background: #1976d2; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 1em; transition: background 0.3s ease; height: 46px; }
        .search-btn:hover { background: #1565c0; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; font-weight: bold; }
        .severity-low { color: #388e3c; font-weight: bold; }
        .tag { display: inline-block; background: #e3f2fd; color: #1976d2; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #1976d2; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-left: 4px solid #1976d2; transition: all 0.3s ease; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 8px 15px rgba(0,0,0,0.2); }
        .stat-number { font-size: 2em; font-weight: bold; color: #1976d2; }
        .stat-label { color: #666; font-size: 0.9em; margin-top: 5px; }
        .alert-item, .cve-item, .news-item { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 15px; overflow: hidden; cursor: pointer; transition: all 0.3s ease; }
        .alert-item:hover, .cve-item:hover, .news-item:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        .quick-actions { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .quick-btn { padding: 8px 16px; background: #e3f2fd; color: #1976d2; border: none; border-radius: 20px; cursor: pointer; font-size: 0.9em; transition: all 0.3s ease; }
        .quick-btn:hover { background: #1976d2; color: white; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background: white; margin: 5% auto; padding: 20px; border-radius: 12px; width: 80%; max-width: 700px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-height: 80vh; overflow-y: auto; }
        .close { float: right; font-size: 28px; font-weight: bold; cursor: pointer; line-height: 1; }
        .close:hover { color: #f44336; }
        .results-container { max-height: 600px; overflow-y: auto; }
        .results-info { color: #1976d2; font-weight: 600; margin-bottom: 15px; background: #e3f2fd; padding: 10px; border-radius: 6px; }
        .live-feed { max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 6px; padding: 10px; background: #fafafa; }
        .feed-item { padding: 8px; border-bottom: 1px solid #e0e0e0; font-size: 0.9em; }
        .feed-item:last-child { border-bottom: none; }
        .feed-time { color: #666; font-size: 0.8em; }
        .breach-checker { background: white; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: all 0.3s ease; }
        .breach-checker:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        .breach-checker h3 { color: #1976d2; margin-bottom: 10px; }
        .breach-checker .features { display: flex; gap: 10px; flex-wrap: wrap; margin: 10px 0; }
        .feature-tag { background: #e8f5e8; color: #2e7d32; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
        .settings-section { background: white; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .settings-row { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #e0e0e0; }
        .settings-row:last-child { border-bottom: none; }
        .theme-selector { display: flex; gap: 10px; }
        .theme-option { width: 30px; height: 30px; border-radius: 50%; cursor: pointer; border: 3px solid transparent; transition: all 0.3s ease; }
        .theme-option:hover, .theme-option.active { border-color: #1976d2; transform: scale(1.1); }
        .theme-blue { background: linear-gradient(135deg, #1976d2, #42a5f5); }
        .theme-dark { background: linear-gradient(135deg, #212121, #424242); }
        .theme-green { background: linear-gradient(135deg, #388e3c, #66bb6a); }
        .theme-purple { background: linear-gradient(135deg, #7b1fa2, #ba68c8); }
        .switch { position: relative; display: inline-block; width: 60px; height: 34px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: #1976d2; }
        input:checked + .slider:before { transform: translateX(26px); }
        .news-category { padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; color: white; }
        .category-vulnerabilities { background: #d32f2f; }
        .category-breaches { background: #f57c00; }
        .category-malware { background: #9c27b0; }
        .category-government { background: #1976d2; }
        .category-threat { background: #388e3c; }
        .priority-critical { border-left: 4px solid #d32f2f; }
        .priority-high { border-left: 4px solid #f57c00; }
        .priority-medium { border-left: 4px solid #fbc02d; }
        .priority-low { border-left: 4px solid #388e3c; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ CyberClause Dashboard v3.1</h1>
            <div class="header-actions">
                <span class="status-indicator" id="api-status">🔑 API Ready</span>
                <span class="status-indicator" id="refresh-status">🔄 Live</span>
                <button class="btn btn-secondary" onclick="refreshAll()">🔄 Refresh</button>
            </div>
        </header>

        <nav class="sidebar">
            <a class="nav-item active" onclick="showTab('dashboard')" id="nav-dashboard">
                <i>📊</i> Dashboard
            </a>
            <a class="nav-item" onclick="showTab('cve')" id="nav-cve">
                <i>🔍</i> CVE Search
            </a>
            <a class="nav-item" onclick="showTab('news')" id="nav-news">
                <i>📰</i> News Feed
            </a>
            <a class="nav-item" onclick="showTab('grc')" id="nav-grc">
                <i>📚</i> GRC Documents
            </a>
            <a class="nav-item" onclick="showTab('breach')" id="nav-breach">
                <i>🔓</i> Breach Checker
            </a>
            <a class="nav-item" onclick="showTab('settings')" id="nav-settings">
                <i>⚙️</i> Settings
            </a>
        </nav>

        <main class="main-content">
            <!-- Tab 1: Dashboard -->
            <div id="tab-dashboard" class="tab-content active">
                <div class="content-header">
                    <h2>📊 Live Cybersecurity Operations Center</h2>
                    <div>
                        <button class="btn btn-primary" onclick="refreshDashboard()">🔄 Refresh</button>
                        <button class="btn btn-secondary" onclick="exportDashboard()">📊 Export</button>
                    </div>
                </div>

                <!-- Live Statistics -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" id="critical-cves">-</div>
                        <div class="stat-label">Critical CVEs (7 days)</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="active-threats">-</div>
                        <div class="stat-label">Active Threats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="news-alerts">-</div>
                        <div class="stat-label">News Alerts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="last-update">-</div>
                        <div class="stat-label">Last Update</div>
                    </div>
                </div>

                <div class="grid-2">
                    <!-- Live Alerts -->
                    <div class="card">
                        <div class="card-header">🚨 Critical Alerts</div>
                        <div class="card-body">
                            <div id="live-alerts" class="live-feed">
                                <div class="loading">
                                    <div class="spinner"></div>
                                    Loading alerts...
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent CVEs -->
                    <div class="card">
                        <div class="card-header">🔍 Recent Critical CVEs</div>
                        <div class="card-body">
                            <div id="recent-cves" class="live-feed">
                                <div class="loading">
                                    <div class="spinner"></div>
                                    Loading CVEs...
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="grid-2">
                    <!-- Live News -->
                    <div class="card">
                        <div class="card-header">📰 Threat Intelligence Feed</div>
                        <div class="card-body">
                            <div id="live-news" class="live-feed">
                                <div class="loading">
                                    <div class="spinner"></div>
                                    Loading news...
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- System Status -->
                    <div class="card">
                        <div class="card-header">⚡ System Status</div>
                        <div class="card-body">
                            <div id="system-status">
                                <div class="settings-row">
                                    <span>API Connection</span>
                                    <span id="api-connection" class="tag">Checking...</span>
                                </div>
                                <div class="settings-row">
                                    <span>Data Sources</span>
                                    <span id="data-sources" class="tag">Checking...</span>
                                </div>
                                <div class="settings-row">
                                    <span>Auto Refresh</span>
                                    <span id="auto-refresh-status" class="tag">Active</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 2: CVE Search -->
            <div id="tab-cve" class="tab-content">
                <div class="content-header">
                    <h2>🔍 CVE Search & Analysis</h2>
                    <button class="btn btn-primary" onclick="clearCVECache()">🗑️ Clear Cache</button>
                </div>

                <div class="search-container">
                    <div class="search-row">
                        <div class="search-group">
                            <label for="cve-search-query">🔍 Search CVEs</label>
                            <input type="text" id="cve-search-query" class="search-input" placeholder="CVE ID, product name, or keyword...">
                        </div>
                        <div class="search-group">
                            <label for="cve-severity-filter">⚠️ Severity</label>
                            <select id="cve-severity-filter" class="search-select">
                                <option value="">All Severities</option>
                                <option value="CRITICAL">🔴 Critical</option>
                                <option value="HIGH">🟠 High</option>
                                <option value="MEDIUM">🟡 Medium</option>
                                <option value="LOW">🟢 Low</option>
                            </select>
                        </div>
                        <div class="search-group">
                            <label for="cve-days-filter">📅 Time Range</label>
                            <select id="cve-days-filter" class="search-select">
                                <option value="">All Time</option>
                                <option value="1">Last 24 hours</option>
                                <option value="3">Last 3 days</option>
                                <option value="7">Last week</option>
                                <option value="30">Last month</option>
                            </select>
                        </div>
                        <button onclick="searchCVEs()" class="search-btn">🔍 Search</button>
                    </div>

                    <div class="quick-actions">
                        <button class="quick-btn" onclick="quickCVESearch('critical')">🔴 Critical CVEs</button>
                        <button class="quick-btn" onclick="quickCVESearch('windows')">🪟 Windows</button>
                        <button class="quick-btn" onclick="quickCVESearch('apache')">🌐 Apache</button>
                        <button class="quick-btn" onclick="quickCVESearch('recent')">🆕 Recent</button>
                        <button class="quick-btn" onclick="quickCVESearch('trending')">📈 Trending</button>
                    </div>
                </div>

                <div id="cve-results" class="results-container">
                    <div class="card">
                        <div class="card-body">
                            <h3>🔍 Ready to Search</h3>
                            <p>Enter search criteria above to find CVEs in the live NVD database.</p>
                            <p><strong>Examples:</strong></p>
                            <ul>
                                <li>Search for specific CVE: <code>CVE-2024-1234</code></li>
                                <li>Search by product: <code>Apache HTTP Server</code></li>
                                <li>Search by vendor: <code>Microsoft</code></li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 3: News Feed -->
            <div id="tab-news" class="tab-content">
                <div class="content-header">
                    <h2>📰 Cybersecurity News & Threat Intelligence</h2>
                    <div>
                        <button class="btn btn-primary" onclick="refreshNews()">🔄 Refresh</button>
                        <button class="btn btn-secondary" onclick="exportNews()">📊 Export</button>
                    </div>
                </div>

                <div class="search-container">
                    <div class="search-row">
                        <div class="search-group">
                            <label for="news-search-query">🔍 Search News</label>
                            <input type="text" id="news-search-query" class="search-input" placeholder="Keywords, source, or topic...">
                        </div>
                        <div class="search-group">
                            <label for="news-category-filter">📂 Category</label>
                            <select id="news-category-filter" class="search-select">
                                <option value="">All Categories</option>
                                <option value="Government Advisory">🏛️ Government</option>
                                <option value="Vulnerabilities">🔍 Vulnerabilities</option>
                                <option value="Data Breaches">🔓 Breaches</option>
                                <option value="Malware">🦠 Malware</option>
                                <option value="Threat Intelligence">🎯 Threat Intel</option>
                            </select>
                        </div>
                        <div class="search-group">
                            <label for="news-threat-filter">⚠️ Threat Level</label>
                            <select id="news-threat-filter" class="search-select">
                                <option value="">All Levels</option>
                                <option value="Critical">🔴 Critical</option>
                                <option value="High">🟠 High</option>
                                <option value="Medium">🟡 Medium</option>
                                <option value="Low">🟢 Low</option>
                            </select>
                        </div>
                        <button onclick="searchNews()" class="search-btn">🔍 Search</button>
                    </div>

                    <div class="quick-actions">
                        <button class="quick-btn" onclick="quickNewsSearch('breaking')">⚡ Breaking</button>
                        <button class="quick-btn" onclick="quickNewsSearch('critical')">🔴 Critical</button>
                        <button class="quick-btn" onclick="quickNewsSearch('breaches')">🔓 Breaches</button>
                        <button class="quick-btn" onclick="quickNewsSearch('malware')">🦠 Malware</button>
                        <button class="quick-btn" onclick="quickNewsSearch('government')">🏛️ Gov Advisory</button>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" id="total-news">-</div>
                        <div class="stat-label">Total Articles</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="breaking-news">-</div>
                        <div class="stat-label">Breaking News</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="high-priority-news">-</div>
                        <div class="stat-label">High Priority</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="news-sources">-</div>
                        <div class="stat-label">Active Sources</div>
                    </div>
                </div>

                <div id="news-results" class="results-container">
                    <div class="loading">
                        <div class="spinner"></div>
                        Loading latest cybersecurity news...
                    </div>
                </div>
            </div>

            <!-- Tab 4: GRC Documents -->
            <div id="tab-grc" class="tab-content">
                <div class="content-header">
                    <h2>📚 GRC Documents & Frameworks</h2>
                    <button class="btn btn-primary" onclick="refreshGRCDocs()">🔄 Refresh</button>
                </div>

                <div class="search-container">
                    <div class="search-row">
                        <div class="search-group">
                            <label for="grc-search-query">🔍 Search Documents</label>
                            <input type="text" id="grc-search-query" class="search-input" placeholder="Framework name, standard, or keyword...">
                        </div>
                        <div class="search-group">
                            <label for="grc-category-filter">📂 Category</label>
                            <select id="grc-category-filter" class="search-select">
                                <option value="">All Categories</option>
                                <option value="Framework">Frameworks</option>
                                <option value="Standard">Standards</option>
                                <option value="Policy">Policies</option>
                                <option value="Guideline">Guidelines</option>
                                <option value="Regulation">Regulations</option>
                            </select>
                        </div>
                        <div class="search-group">
                            <label for="grc-compliance-filter">⚖️ Compliance Level</label>
                            <select id="grc-compliance-filter" class="search-select">
                                <option value="">All Levels</option>
                                <option value="Mandatory">Mandatory</option>
                                <option value="Recommended">Recommended</option>
                                <option value="Voluntary">Voluntary</option>
                            </select>
                        </div>
                        <button onclick="searchGRCDocs()" class="search-btn">🔍 Search</button>
                    </div>

                    <div class="quick-actions">
                        <button class="quick-btn" onclick="quickGRCSearch('nist')">🏛️ NIST</button>
                        <button class="quick-btn" onclick="quickGRCSearch('iso')">🌐 ISO</button>
                        <button class="quick-btn" onclick="quickGRCSearch('gdpr')">🇪🇺 GDPR</button>
                        <button class="quick-btn" onclick="quickGRCSearch('sox')">💼 SOX</button>
                        <button class="quick-btn" onclick="quickGRCSearch('hipaa')">🏥 HIPAA</button>
                    </div>
                </div>

                <div id="grc-results" class="results-container">
                    <div class="card">
                        <div class="card-body">
                            <h3>📚 GRC Document Library</h3>
                            <p>Search and explore cybersecurity frameworks, policies, and compliance documents.</p>
                            <div class="loading">
                                <div class="spinner"></div>
                                Loading GRC documents...
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 5: Breach Checker -->
            <div id="tab-breach" class="tab-content">
                <div class="content-header">
                    <h2>🔓 Breach Checker & Monitoring</h2>
                    <button class="btn btn-primary" onclick="refreshBreachData()">🔄 Refresh</button>
                </div>

                <div class="card">
                    <div class="card-header">🔍 Credible Breach Checking Services</div>
                    <div class="card-body">
                        <p>Access verified and trusted breach checking services to monitor for data exposures.</p>
                    </div>
                </div>

                <div id="breach-checkers" class="grid">
                    <div class="loading">
                        <div class="spinner"></div>
                        Loading breach checkers...
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">📊 Recent Breach Activity</div>
                    <div class="card-body">
                        <div id="recent-breaches">
                            <div class="loading">
                                <div class="spinner"></div>
                                Loading recent breach data...
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 6: Settings -->
            <div id="tab-settings" class="tab-content">
                <div class="content-header">
                    <h2>⚙️ Dashboard Settings</h2>
                    <button class="btn btn-secondary" onclick="saveSettings()">💾 Save Settings</button>
                </div>

                <div class="settings-section">
                    <h3>🎨 Appearance</h3>
                    <div class="settings-row">
                        <span>Theme</span>
                        <div class="theme-selector">
                            <div class="theme-option theme-blue active" onclick="setTheme('blue')" title="Blue Theme"></div>
                            <div class="theme-option theme-dark" onclick="setTheme('dark')" title="Dark Theme"></div>
                            <div class="theme-option theme-green" onclick="setTheme('green')" title="Green Theme"></div>
                            <div class="theme-option theme-purple" onclick="setTheme('purple')" title="Purple Theme"></div>
                        </div>
                    </div>
                    <div class="settings-row">
                        <span>Auto-refresh Dashboard</span>
                        <label class="switch">
                            <input type="checkbox" id="auto-refresh-toggle" checked onchange="toggleAutoRefresh()">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="settings-row">
                        <span>Refresh Interval (seconds)</span>
                        <select id="refresh-interval" onchange="updateRefreshInterval()">
                            <option value="30">30 seconds</option>
                            <option value="60">1 minute</option>
                            <option value="300" selected>5 minutes</option>
                            <option value="600">10 minutes</option>
                            <option value="1800">30 minutes</option>
                        </select>
                    </div>
                </div>

                <div class="settings-section">
                    <h3>🔑 API Configuration</h3>
                    <div class="settings-row">
                        <span>NVD API Key</span>
                        <div>
                            <input type="password" id="nvd-api-key" placeholder="Enter NVD API key" style="margin-right: 10px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 300px;">
                            <button class="btn btn-primary" onclick="saveAPIKey('nvd')">Save</button>
                        </div>
                    </div>
                    <div class="settings-row">
                        <span>API Status</span>
                        <span id="api-status-display" class="tag">Checking...</span>
                    </div>
                </div>

                <div class="settings-section">
                    <h3>📊 Data Management</h3>
                    <div class="settings-row">
                        <span>Clear Cache</span>
                        <button class="btn btn-warning" onclick="clearAllCache()">🗑️ Clear All Cache</button>
                    </div>
                    <div class="settings-row">
                        <span>Export Data</span>
                        <div>
                            <button class="btn btn-secondary" onclick="exportData('json')">📄 JSON</button>
                            <button class="btn btn-secondary" onclick="exportData('csv')" style="margin-left: 10px;">📊 CSV</button>
                        </div>
                    </div>
                </div>

                <div class="settings-section">
                    <h3>ℹ️ About</h3>
                    <div class="settings-row">
                        <span>Version</span>
                        <span>CyberClause Dashboard v3.1</span>
                    </div>
                    <div class="settings-row">
                        <span>Mode</span>
                        <span>6-Tab Interactive (Dashboard, CVE, News, GRC, Breach, Settings)</span>
                    </div>
                    <div class="settings-row">
                        <span>Data Source</span>
                        <span>NVD API, RSS Feeds, Static Documents</span>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Modal for detailed views -->
    <div id="detail-modal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <div id="modal-body">
                <!-- Details will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        let currentTab = 'dashboard';
        let autoRefreshEnabled = true;
        let refreshInterval = 300000; // 5 minutes
        let refreshTimer;
        let currentSettings = {};

        // Initialize
        window.onload = () => {
            showTab('dashboard');
            startAutoRefresh();
            loadDashboardData();
            loadSettings();
        };

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));

            // Show selected tab
            document.getElementById(`tab-${tabName}`).classList.add('active');
            document.getElementById(`nav-${tabName}`).classList.add('active');

            currentTab = tabName;

            // Load tab-specific data
            loadTabData(tabName);
        }

        function loadTabData(tabName) {
            switch(tabName) {
                case 'dashboard':
                    loadDashboardData();
                    break;
                case 'cve':
                    // CVE search is interactive, no initial load needed
                    break;
                case 'news':
                    loadNewsData();
                    break;
                case 'grc':
                    loadGRCDocuments();
                    break;
                case 'breach':
                    loadBreachCheckers();
                    break;
                case 'settings':
                    loadSettings();
                    break;
            }
        }

        function loadDashboardData() {
            // Load statistics
            fetch('/api/dashboard/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('critical-cves').textContent = data.critical_cves || 0;
                    document.getElementById('active-threats').textContent = data.active_threats || 0;
                    document.getElementById('news-alerts').textContent = data.news_alerts || 0;
                    document.getElementById('last-update').textContent = data.last_update || 'Unknown';
                })
                .catch(error => console.error('Error loading stats:', error));

            // Load live components
            loadLiveAlerts();
            loadRecentCVEs();
            loadLiveNews();
            loadSystemStatus();
        }

        function loadLiveAlerts() {
            fetch('/api/dashboard/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('live-alerts');
                    if (data.alerts && data.alerts.length > 0) {
                        container.innerHTML = data.alerts.map(alert => `
                            <div class="feed-item">
                                <div><strong class="severity-${alert.severity.toLowerCase()}">${alert.title}</strong></div>
                                <div>${alert.description}</div>
                                <div class="feed-time">${formatTime(alert.time)}</div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<div class="feed-item">No critical alerts at this time</div>';
                    }
                })
                .catch(error => {
                    document.getElementById('live-alerts').innerHTML = '<div class="feed-item">Error loading alerts</div>';
                });
        }

        function loadRecentCVEs() {
            fetch('/api/cve/recent?limit=10')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('recent-cves');
                    if (data.cves && data.cves.length > 0) {
                        container.innerHTML = data.cves.map(cve => `
                            <div class="feed-item" onclick="showCVEDetails('${cve.cve_id}')">
                                <div><strong>${cve.cve_id}</strong> - <span class="severity-${cve.severity.toLowerCase()}">${cve.severity}</span></div>
                                <div>${cve.description.substring(0, 100)}...</div>
                                <div class="feed-time">CVSS: ${cve.cvss_score || 'N/A'} | ${formatTime(cve.published)}</div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<div class="feed-item">No recent critical CVEs</div>';
                    }
                })
                .catch(error => {
                    document.getElementById('recent-cves').innerHTML = '<div class="feed-item">Error loading CVEs</div>';
                });
        }

        function loadLiveNews() {
            fetch('/api/news/recent?limit=10')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('live-news');
                    if (data.news && data.news.length > 0) {
                        container.innerHTML = data.news.map(item => `
                            <div class="feed-item" onclick="openLink('${item.url}')">
                                <div><strong>${item.title}</strong></div>
                                <div>${item.description.substring(0, 100)}...</div>
                                <div class="feed-time">${item.source} | ${formatTime(item.published)}</div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<div class="feed-item">No recent news available</div>';
                    }
                })
                .catch(error => {
                    document.getElementById('live-news').innerHTML = '<div class="feed-item">Error loading news</div>';
                });
        }

        function loadSystemStatus() {
            fetch('/api/system/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('api-connection').textContent = data.api_status || 'Unknown';
                    document.getElementById('data-sources').textContent = data.data_sources || 'Unknown';
                    document.getElementById('auto-refresh-status').textContent = autoRefreshEnabled ? 'Active' : 'Disabled';
                })
                .catch(error => console.error('Error loading system status:', error));
        }

        function loadNewsData() {
            // Load news statistics
            fetch('/api/news/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-news').textContent = data.total_articles || 0;
                    document.getElementById('breaking-news').textContent = data.breaking_news_count || 0;
                    document.getElementById('high-priority-news').textContent = data.high_priority_count || 0;
                    document.getElementById('news-sources').textContent = Object.keys(data.most_active_sources || {}).length;
                })
                .catch(error => console.error('Error loading news stats:', error));

            // Load all news
            fetch('/api/news/all?limit=50')
                .then(response => response.json())
                .then(data => {
                    displayNewsResults(data.news, data.total);
                })
                .catch(error => {
                    document.getElementById('news-results').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Loading Error</h3>
                                <p>Failed to load news. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function searchNews() {
            const query = document.getElementById('news-search-query').value;
            const category = document.getElementById('news-category-filter').value;
            const threatLevel = document.getElementById('news-threat-filter').value;

            showLoading('news-results');

            const params = new URLSearchParams();
            if (query) params.append('query', query);
            if (category) params.append('category', category);
            if (threatLevel) params.append('threat_level', threatLevel);

            fetch(`/api/news/search?${params}`)
                .then(response => response.json())
                .then(data => {
                    displayNewsResults(data.news, data.total);
                })
                .catch(error => {
                    document.getElementById('news-results').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Search Error</h3>
                                <p>Failed to search news. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function quickNewsSearch(type) {
            const queries = {
                'breaking': { threat_level: 'Critical' },
                'critical': { threat_level: 'Critical' },
                'breaches': { category: 'Data Breaches' },
                'malware': { category: 'Malware' },
                'government': { category: 'Government Advisory' }
            };

            const params = queries[type];
            if (params.category) document.getElementById('news-category-filter').value = params.category;
            if (params.threat_level) document.getElementById('news-threat-filter').value = params.threat_level;

            searchNews();
        }

        function displayNewsResults(news, total) {
            const container = document.getElementById('news-results');

            if (!news || news.length === 0) {
                container.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h3>No News Found</h3>
                            <p>No news articles found matching your criteria.</p>
                        </div>
                    </div>
                `;
                return;
            }

            let html = `<div class="results-info">Found ${total} article(s)</div>`;

            news.forEach(article => {
                const priorityClass = article.priority_score >= 0.7 ? 'priority-critical' : 
                                   article.priority_score >= 0.5 ? 'priority-high' : 
                                   article.priority_score >= 0.3 ? 'priority-medium' : 'priority-low';

                const categoryClass = `category-${article.category.toLowerCase().replace(/\\s+/g, '')}`;
                const published = new Date(article.published).toLocaleDateString();

                html += `
                    <div class="news-item ${priorityClass}" onclick="openLink('${article.url}')">
                        <div class="card-header">
                            <span style="font-weight: bold;">${article.title}</span>
                            <span class="news-category ${categoryClass}">${article.category}</span>
                            <span style="float: right; font-size: 0.9em;">${published}</span>
                        </div>
                        <div class="card-body">
                            <p>${article.description}</p>
                            <div style="margin-top: 10px;">
                                <span class="tag">📰 ${article.source}</span>
                                <span class="tag">⚠️ ${article.threat_level}</span>
                                <span class="tag">📈 Priority: ${(article.priority_score * 100).toFixed(0)}%</span>
                                ${article.entities.slice(0, 3).map(e => `<span class="tag">${e}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // CVE Search Functions
        function searchCVEs() {
            const query = document.getElementById('cve-search-query').value;
            const severity = document.getElementById('cve-severity-filter').value;
            const days = document.getElementById('cve-days-filter').value;

            if (!query && !severity && !days) {
                alert('Please enter a search query, select severity, or choose a time range');
                return;
            }

            showLoading('cve-results');

            const params = new URLSearchParams();
            if (query) params.append('query', query);
            if (severity) params.append('severity', severity);
            if (days) params.append('days_back', days);

            fetch(`/api/cve/search?${params}`)
                .then(response => response.json())
                .then(data => {
                    displayCVEResults(data.results, data.total);
                })
                .catch(error => {
                    document.getElementById('cve-results').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Search Error</h3>
                                <p>Failed to search CVEs. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function quickCVESearch(type) {
            const queries = {
                'critical': { severity: 'CRITICAL', days_back: 7 },
                'windows': { query: 'windows' },
                'apache': { query: 'apache' },
                'recent': { days_back: 3 },
                'trending': { days_back: 14, severity: 'HIGH' }
            };

            const params = queries[type];
            if (params.query) document.getElementById('cve-search-query').value = params.query;
            if (params.severity) document.getElementById('cve-severity-filter').value = params.severity;
            if (params.days_back) document.getElementById('cve-days-filter').value = params.days_back;

            searchCVEs();
        }

        function displayCVEResults(results, total) {
            const container = document.getElementById('cve-results');

            if (!results || results.length === 0) {
                container.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h3>No Results Found</h3>
                            <p>No CVEs found matching your search criteria. Try different keywords or filters.</p>
                        </div>
                    </div>
                `;
                return;
            }

            let html = `<div class="results-info">Found ${total} CVE(s)</div>`;

            results.forEach(cve => {
                const severityClass = `severity-${cve.severity.toLowerCase()}`;
                const published = new Date(cve.published).toLocaleDateString();

                html += `
                    <div class="cve-item" onclick="showCVEDetails('${cve.cve_id}')">
                        <div class="card-header">
                            <span style="color: #1976d2; font-weight: bold;">${cve.cve_id}</span>
                            - <span class="${severityClass}">${cve.severity}</span>
                            (CVSS: ${cve.cvss_score || 'N/A'})
                            <span style="float: right; font-size: 0.9em;">${published}</span>
                        </div>
                        <div class="card-body">
                            <p>${cve.description.substring(0, 200)}...</p>
                            <div style="margin-top: 10px;">
                                ${cve.affected_products.slice(0, 3).map(p => `<span class="tag">${p}</span>`).join('')}
                                ${cve.affected_products.length > 3 ? `<span class="tag">+${cve.affected_products.length - 3} more</span>` : ''}
                            </div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // GRC and Breach functions (keeping existing)
        function loadGRCDocuments() {
            showLoading('grc-results');

            fetch('/api/grc/documents')
                .then(response => response.json())
                .then(data => {
                    displayGRCResults(data.documents, data.total);
                })
                .catch(error => {
                    document.getElementById('grc-results').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Loading Error</h3>
                                <p>Failed to load GRC documents. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function searchGRCDocs() {
            const query = document.getElementById('grc-search-query').value;
            const category = document.getElementById('grc-category-filter').value;
            const compliance = document.getElementById('grc-compliance-filter').value;

            showLoading('grc-results');

            const params = new URLSearchParams();
            if (query) params.append('query', query);
            if (category) params.append('category', category);
            if (compliance) params.append('compliance', compliance);

            fetch(`/api/grc/search?${params}`)
                .then(response => response.json())
                .then(data => {
                    displayGRCResults(data.documents, data.total);
                })
                .catch(error => {
                    document.getElementById('grc-results').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Search Error</h3>
                                <p>Failed to search GRC documents. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function quickGRCSearch(type) {
            const queries = {
                'nist': { query: 'NIST' },
                'iso': { query: 'ISO 27001' },
                'gdpr': { query: 'GDPR' },
                'sox': { query: 'SOX' },
                'hipaa': { query: 'HIPAA' }
            };

            const params = queries[type];
            if (params.query) document.getElementById('grc-search-query').value = params.query;
            if (params.category) document.getElementById('grc-category-filter').value = params.category;

            searchGRCDocs();
        }

        function displayGRCResults(documents, total) {
            const container = document.getElementById('grc-results');

            if (!documents || documents.length === 0) {
                container.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h3>No Documents Found</h3>
                            <p>No GRC documents found matching your criteria.</p>
                        </div>
                    </div>
                `;
                return;
            }

            let html = `<div class="results-info">Found ${total} document(s)</div>`;

            documents.forEach(doc => {
                html += `
                    <div class="card" onclick="showDocumentDetails('${doc.title}')">
                        <div class="card-header">
                            ${doc.title} 
                            <span class="tag">${doc.document_type}</span>
                        </div>
                        <div class="card-body">
                            <p><strong>Organization:</strong> ${doc.source}</p>
                            <p><strong>Category:</strong> ${doc.category}</p>
                            <p><strong>Compliance:</strong> ${doc.compliance_level}</p>
                            <p>${doc.description}</p>
                            <p><small>Last Updated: ${doc.last_updated}</small></p>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        function loadBreachCheckers() {
            fetch('/api/breach/checkers')
                .then(response => response.json())
                .then(data => {
                    displayBreachCheckers(data.checkers);
                })
                .catch(error => {
                    document.getElementById('breach-checkers').innerHTML = `
                        <div class="card">
                            <div class="card-body">
                                <h3 style="color: #d32f2f;">Loading Error</h3>
                                <p>Failed to load breach checkers. Please try again.</p>
                            </div>
                        </div>
                    `;
                });
        }

        function displayBreachCheckers(checkers) {
            const container = document.getElementById('breach-checkers');

            if (!checkers || checkers.length === 0) {
                container.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h3>No Breach Checkers Available</h3>
                            <p>No verified breach checking services are currently available.</p>
                        </div>
                    </div>
                `;
                return;
            }

            let html = '';

            checkers.forEach(checker => {
                html += `
                    <div class="breach-checker">
                        <h3>${checker.icon} ${checker.name}</h3>
                        <p>${checker.description}</p>
                        <div class="features">
                            ${checker.features.map(feature => `<span class="feature-tag">${feature}</span>`).join('')}
                        </div>
                        <div style="margin-top: 15px;">
                            <span class="tag">${checker.free ? 'Free' : 'Paid'}</span>
                            <span class="tag">${checker.reliability}</span>
                            ${checker.api_available ? '<span class="tag">API Available</span>' : ''}
                        </div>
                        <div style="margin-top: 15px;">
                            <button class="btn btn-primary" onclick="openLink('${checker.url}')">🔗 Visit Site</button>
                            <button class="btn btn-secondary" onclick="openLink('${checker.check_url.replace('{email}', 'test@example.com')}')">🔍 Example Check</button>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // Settings Functions (FIXED)
        function loadSettings() {
            fetch('/api/settings')
                .then(response => response.json())
                .then(data => {
                    currentSettings = data;
                    // Update UI with current settings
                    document.getElementById('auto-refresh-toggle').checked = data.auto_refresh !== false;
                    document.getElementById('refresh-interval').value = data.refresh_interval || 300;
                    // Update API status
                    document.getElementById('api-status-display').textContent = data.api_status || 'Not configured';

                    // Load current API key (if any)
                    if (data.nvd_api_key) {
                        document.getElementById('nvd-api-key').value = '••••••••'; // Show masked key
                    }
                })
                .catch(error => {
                    console.error('Error loading settings:', error);
                    // Set defaults
                    currentSettings = {
                        auto_refresh: true,
                        refresh_interval: 300,
                        api_status: 'Unknown'
                    };
                });
        }

        function saveSettings() {
            const settings = {
                auto_refresh: document.getElementById('auto-refresh-toggle').checked,
                refresh_interval: parseInt(document.getElementById('refresh-interval').value),
                theme: getSelectedTheme()
            };

            fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Settings saved successfully');
                    currentSettings = { ...currentSettings, ...settings };
                    // Apply settings immediately
                    autoRefreshEnabled = settings.auto_refresh;
                    refreshInterval = settings.refresh_interval * 1000;
                    if (autoRefreshEnabled) {
                        startAutoRefresh();
                    } else {
                        stopAutoRefresh();
                    }
                } else {
                    alert('Failed to save settings: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error saving settings:', error);
                alert('Failed to save settings');
            });
        }

        function saveAPIKey(service) {
            const keyInput = document.getElementById(`${service}-api-key`);
            const key = keyInput.value.trim();

            if (!key || key === '••••••••') {
                alert('Please enter a valid API key');
                return;
            }

            fetch('/api/settings/api-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service: service, key: key })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('API key saved successfully');
                    keyInput.value = '••••••••'; // Mask the key
                    loadSettings(); // Reload to get updated status
                } else {
                    alert('Failed to save API key: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error saving API key:', error);
                alert('Failed to save API key');
            });
        }

        function getSelectedTheme() {
            const activeTheme = document.querySelector('.theme-option.active');
            if (activeTheme.classList.contains('theme-blue')) return 'blue';
            if (activeTheme.classList.contains('theme-dark')) return 'dark';
            if (activeTheme.classList.contains('theme-green')) return 'green';
            if (activeTheme.classList.contains('theme-purple')) return 'purple';
            return 'blue';
        }

        function setTheme(theme) {
            document.querySelectorAll('.theme-option').forEach(opt => opt.classList.remove('active'));
            document.querySelector(`.theme-${theme}`).classList.add('active');
            // Apply theme changes to document (you can expand this)
            document.body.className = `theme-${theme}`;
        }

        function toggleAutoRefresh() {
            autoRefreshEnabled = document.getElementById('auto-refresh-toggle').checked;
            if (autoRefreshEnabled) {
                startAutoRefresh();
                document.getElementById('auto-refresh-status').textContent = 'Active';
            } else {
                stopAutoRefresh();
                document.getElementById('auto-refresh-status').textContent = 'Disabled';
            }
        }

        function updateRefreshInterval() {
            refreshInterval = parseInt(document.getElementById('refresh-interval').value) * 1000;
            if (autoRefreshEnabled) {
                stopAutoRefresh();
                startAutoRefresh();
            }
        }

        function clearAllCache() {
            if (confirm('Are you sure you want to clear all cached data?')) {
                fetch('/api/cache/clear', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Cache cleared successfully');
                        } else {
                            alert('Failed to clear cache');
                        }
                    })
                    .catch(error => {
                        console.error('Error clearing cache:', error);
                        alert('Failed to clear cache');
                    });
            }
        }

        function exportData(format) {
            window.open(`/api/export/${format}`, '_blank');
        }

        // Modal and utility functions
        function showCVEDetails(cveId) {
            showLoading('modal-body');
            document.getElementById('detail-modal').style.display = 'block';

            fetch(`/api/cve/details/${cveId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        displayCVEDetailsModal(data.cve_data);
                    } else {
                        document.getElementById('modal-body').innerHTML = `
                            <h3>Error</h3>
                            <p>Failed to load CVE details: ${data.error}</p>
                        `;
                    }
                })
                .catch(error => {
                    document.getElementById('modal-body').innerHTML = `
                        <h3>Error</h3>
                        <p>Failed to load CVE details. Please try again.</p>
                    `;
                });
        }

        function displayCVEDetailsModal(cve) {
            const published = new Date(cve.published).toLocaleDateString();
            const severityClass = `severity-${cve.severity.toLowerCase()}`;

            document.getElementById('modal-body').innerHTML = `
                <h2>${cve.cve_id}</h2>
                <div style="margin: 15px 0;">
                    <span class="${severityClass}" style="font-size: 1.2em;">${cve.severity}</span>
                    <span style="margin-left: 20px;">CVSS: ${cve.cvss_score || 'N/A'}</span>
                    <span style="margin-left: 20px;">Published: ${published}</span>
                </div>

                <h3>Description</h3>
                <p style="margin-bottom: 20px;">${cve.description}</p>

                ${cve.impact_level ? `
                    <h3>Impact Assessment</h3>
                    <p style="margin-bottom: 10px;"><strong>${cve.impact_level}</strong></p>
                    <p style="margin-bottom: 20px;">${cve.recommended_action}</p>
                ` : ''}

                ${cve.affected_products && cve.affected_products.length > 0 ? `
                    <h3>Affected Products</h3>
                    <div style="margin-bottom: 20px;">
                        ${cve.affected_products.map(p => `<span class="tag">${p}</span>`).join('')}
                    </div>
                ` : ''}

                <h3>References</h3>
                <div style="margin-bottom: 20px;">
                    <a href="${cve.source_url}" target="_blank" class="btn btn-primary">🔗 View on NVD</a>
                    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.cve_id}" target="_blank" class="btn btn-secondary">📋 MITRE CVE</a>
                </div>
            `;
        }

        function showDocumentDetails(title) {
            // Implementation for GRC document details
            showLoading('modal-body');
            document.getElementById('detail-modal').style.display = 'block';
            document.getElementById('modal-body').innerHTML = `
                <h2>${title}</h2>
                <p>Document details would be loaded here...</p>
            `;
        }

        function closeModal() {
            document.getElementById('detail-modal').style.display = 'none';
        }

        function showLoading(containerId) {
            document.getElementById(containerId).innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    Loading...
                </div>
            `;
        }

        function refreshAll() {
            fetch('/api/refresh/all', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('All data refreshed successfully');
                        loadTabData(currentTab);
                    } else {
                        alert('Failed to refresh some data sources');
                    }
                })
                .catch(error => {
                    alert('Failed to refresh data');
                });
        }

        function refreshDashboard() {
            loadDashboardData();
        }

        function refreshNews() {
            loadNewsData();
        }

        function refreshGRCDocs() {
            loadGRCDocuments();
        }

        function refreshBreachData() {
            loadBreachCheckers();
        }

        function clearCVECache() {
            fetch('/api/cache/clear', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert('CVE cache cleared successfully');
                })
                .catch(error => {
                    alert('Failed to clear cache');
                });
        }

        function exportDashboard() {
            exportData('json');
        }

        function exportNews() {
            window.open('/api/export/news', '_blank');
        }

        function startAutoRefresh() {
            if (autoRefreshEnabled && !refreshTimer) {
                refreshTimer = setInterval(() => {
                    if (currentTab === 'dashboard') {
                        loadDashboardData();
                    }
                }, refreshInterval);
            }
        }

        function stopAutoRefresh() {
            if (refreshTimer) {
                clearInterval(refreshTimer);
                refreshTimer = null;
            }
        }

        function openLink(url) {
            window.open(url, '_blank');
        }

        function formatTime(timestamp) {
            try {
                return new Date(timestamp).toLocaleString();
            } catch {
                return timestamp;
            }
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('detail-modal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


# API Routes for Dashboard Tab
@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    try:
        # Get recent critical CVEs
        critical_cves = engines['vulnerabilities'].get_recent_critical(days=7)

        # Get recent news alerts
        news_data = engines['news'].get_data({'threat_level': 'High'})

        stats = {
            'critical_cves': len(critical_cves),
            'active_threats': len([cve for cve in critical_cves if cve.get('severity') == 'CRITICAL']),
            'news_alerts': len(news_data[:10]),
            'last_update': datetime.now().strftime('%H:%M:%S')
        }

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/alerts')
def get_dashboard_alerts():
    try:
        # Generate alerts from recent critical CVEs and high-threat news
        alerts = []

        # Add critical CVE alerts
        critical_cves = engines['vulnerabilities'].get_recent_critical(days=3)
        for cve in critical_cves[:5]:
            if cve.get('severity') == 'CRITICAL':
                alerts.append({
                    'title': f"Critical CVE: {cve.get('cve_id')}",
                    'description': cve.get('description', '')[:100] + '...',
                    'severity': 'critical',
                    'time': cve.get('published'),
                    'type': 'CVE'
                })

        # Add high-threat news alerts
        news_data = engines['news'].get_data({'threat_level': 'Critical'})
        for news in news_data[:3]:
            alerts.append({
                'title': news.get('title', ''),
                'description': news.get('description', '')[:100] + '...',
                'severity': 'high',
                'time': news.get('published'),
                'type': 'News'
            })

        # Sort by time (most recent first)
        alerts.sort(key=lambda x: x.get('time', ''), reverse=True)

        return jsonify({'alerts': alerts[:10]})
    except Exception as e:
        return jsonify({'error': str(e), 'alerts': []}), 500


# API Routes for CVE Tab
@app.route('/api/cve/search')
def search_cves_api():
    try:
        query = request.args.get('query', '')
        severity = request.args.get('severity', '')
        days_back = request.args.get('days_back', '')

        days_back_int = int(days_back) if days_back else None

        results = engines['vulnerabilities'].search_cves(
            query=query if query else None,
            severity=severity if severity else None,
            days_back=days_back_int
        )

        return jsonify({
            'results': results,
            'total': len(results),
            'status': 'success'
        })

    except Exception as e:
        return jsonify({
            'results': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/cve/recent')
def get_recent_cves():
    try:
        limit = int(request.args.get('limit', 10))
        recent_cves = engines['vulnerabilities'].get_recent_critical(days=7)

        return jsonify({
            'cves': recent_cves[:limit],
            'total': len(recent_cves),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'cves': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/cve/details/<cve_id>')
def get_cve_details_api(cve_id):
    try:
        cve_detail = engines['vulnerabilities'].get_cve_details(cve_id)

        if cve_detail:
            return jsonify({'success': True, 'cve_data': cve_detail})
        else:
            return jsonify({'success': False, 'error': 'CVE not found'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# API Routes for News Tab (NEW)
@app.route('/api/news/all')
def get_all_news():
    try:
        limit = int(request.args.get('limit', 50))
        news_data = engines['news'].get_data()

        return jsonify({
            'news': news_data[:limit],
            'total': len(news_data),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'news': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/news/search')
def search_news_api():
    try:
        query = request.args.get('query', '')
        category = request.args.get('category', '')
        threat_level = request.args.get('threat_level', '')

        filters = {}
        if category:
            filters['category'] = category
        if threat_level:
            filters['threat_level'] = threat_level

        if query:
            results = engines['news'].search(query, filters)
        else:
            results = engines['news'].get_data(filters)

        return jsonify({
            'news': results,
            'total': len(results),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'news': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/news/stats')
def get_news_stats():
    try:
        stats = engines['news'].get_news_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/news/recent')
def get_recent_news():
    try:
        limit = int(request.args.get('limit', 10))
        news_data = engines['news'].get_data()

        # Sort by relevance and recency
        news_data.sort(key=lambda x: (x.get('relevance_score', 0), x.get('published', '')), reverse=True)

        return jsonify({
            'news': news_data[:limit],
            'total': len(news_data),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'news': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


# API Routes for GRC Documents Tab
@app.route('/api/grc/documents')
def get_grc_documents():
    try:
        documents = engines['cyber_docs'].get_data()

        return jsonify({
            'documents': documents,
            'total': len(documents),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'documents': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/grc/search')
def search_grc_documents():
    try:
        query = request.args.get('query', '')
        category = request.args.get('category', '')
        compliance = request.args.get('compliance', '')

        filters = {}
        if category:
            filters['category'] = category
        if compliance:
            filters['compliance_level'] = compliance

        if query:
            results = engines['cyber_docs'].search(query, filters)
        else:
            results = engines['cyber_docs'].get_data(filters)

        return jsonify({
            'documents': results,
            'total': len(results),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'documents': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


# API Routes for Breach Checker Tab
@app.route('/api/breach/checkers')
def get_breach_checkers():
    try:
        checkers = engines['breaches'].get_breach_checkers()

        return jsonify({
            'checkers': checkers,
            'total': len(checkers),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'checkers': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })


# API Routes for System Status
@app.route('/api/system/status')
def get_system_status():
    try:
        # Check API status
        api_status = api_status_manager.get_api_status('nvd')

        # Check data sources
        sources_ok = 0
        total_sources = len(engines)

        for engine_name, engine in engines.items():
            try:
                # Simple health check
                if hasattr(engine, 'get_statistics'):
                    engine.get_statistics()
                    sources_ok += 1
            except:
                pass

        return jsonify({
            'api_status': api_status['indicator'],
            'data_sources': f"{sources_ok}/{total_sources} OK",
            'status': 'operational'
        })
    except Exception as e:
        return jsonify({
            'api_status': 'Error',
            'data_sources': 'Error',
            'status': 'error',
            'error': str(e)
        })


# API Routes for Settings (FIXED)
@app.route('/api/settings')
def get_settings():
    try:
        settings = api_manager.get_settings()
        api_status = api_status_manager.get_api_status('nvd')

        # Check if API key exists
        nvd_key = api_manager.get_api_key('nvd')

        return jsonify({
            'auto_refresh': settings.get('auto_refresh', True),
            'refresh_interval': settings.get('refresh_intervals', {}).get('vulnerabilities', 300),
            'api_status': api_status['indicator'],
            'nvd_api_key': bool(nvd_key),  # Don't send actual key
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'auto_refresh': True,
            'refresh_interval': 300,
            'api_status': 'Error',
            'nvd_api_key': False,
            'status': 'error',
            'error': str(e)
        })


@app.route('/api/settings', methods=['POST'])
def save_settings():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'error': 'No data provided'})

        # Update settings
        success = api_manager.update_settings({
            'auto_refresh': data.get('auto_refresh', True),
            'refresh_intervals': {
                'vulnerabilities': data.get('refresh_interval', 300)
            },
            'theme': data.get('theme', 'blue')
        })

        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/settings/api-key', methods=['POST'])
def save_api_key():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'error': 'No data provided'})

        service = data.get('service')
        key = data.get('key')

        if not service or not key:
            return jsonify({'success': False, 'error': 'Service and key required'})

        success = api_manager.set_api_key(service, key)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Utility Routes
@app.route('/api/refresh/all', methods=['POST'])
def refresh_all_data():
    try:
        results = {}
        for name, engine in engines.items():
            try:
                results[name] = engine.refresh_data()
            except:
                results[name] = False

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    try:
        engines['vulnerabilities'].clear_cache()
        return jsonify({'success': True, 'message': 'Cache cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/export/<format>')
def export_data(format):
    try:
        # Implementation for data export
        return jsonify({'message': f'Export in {format} format not implemented yet'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/news')
def export_news():
    try:
        news_data = engines['news'].get_data()
        return jsonify({
            'news': news_data,
            'total': len(news_data),
            'exported_at': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def open_browser():
    """Open browser after delay"""
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    print("🛡️  Starting CyberClause Dashboard v3.1 - 6-Tab Mode")
    print("📊 Dashboard | 🔍 CVE Search | 📰 News Feed | 📚 GRC Docs | 🔓 Breach Checker | ⚙️ Settings")
    print("🌐 Dashboard will open at: http://localhost:5000")

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        app.run(debug=False, host='localhost', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down dashboard...")
        print("✅ Dashboard stopped successfully")