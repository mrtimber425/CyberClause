import tkinter as tk
from tkinter import ttk, scrolledtext
import webbrowser
import json


class CVEDetailsViewer:
    """Interactive CVE details viewer with clickable functionality"""

    def __init__(self, parent, api_manager, link_validator):
        self.parent = parent
        self.api_manager = api_manager
        self.link_validator = link_validator
        self.current_cve_data = None

    def show_cve_details(self, cve_data):
        """Show detailed CVE information in a popup window"""
        self.current_cve_data = cve_data

        # Create popup window
        self.detail_window = tk.Toplevel(self.parent)
        self.detail_window.title(f"CVE Details - {cve_data.get('cve_id', 'Unknown')}")
        self.detail_window.geometry("900x700")
        self.detail_window.resizable(True, True)

        # Create notebook for tabs
        notebook = ttk.Notebook(self.detail_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Overview tab
        self.create_overview_tab(notebook, cve_data)

        # Technical details tab
        self.create_technical_tab(notebook, cve_data)

        # Links and resources tab
        self.create_links_tab(notebook, cve_data)

        # Mitigation tab
        self.create_mitigation_tab(notebook, cve_data)

    def create_overview_tab(self, notebook, cve_data):
        """Create overview tab"""
        overview_frame = ttk.Frame(notebook)
        notebook.add(overview_frame, text="📋 Overview")

        # Scrollable content
        canvas = tk.Canvas(overview_frame)
        scrollbar = ttk.Scrollbar(overview_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # CVE Header
        header_frame = ttk.LabelFrame(scrollable_frame, text="CVE Information", padding="10")
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # CVE ID and severity
        id_frame = ttk.Frame(header_frame)
        id_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(id_frame, text="CVE ID:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Label(id_frame, text=cve_data.get('cve_id', 'Unknown'),
                  font=('Arial', 12)).pack(side=tk.LEFT, padx=(10, 0))

        # Severity badge
        severity = cve_data.get('severity', 'Unknown')
        severity_colors = {
            'Critical': '#d32f2f',
            'High': '#f57c00',
            'Medium': '#fbc02d',
            'Low': '#388e3c'
        }

        severity_frame = ttk.Frame(id_frame)
        severity_frame.pack(side=tk.RIGHT)

        severity_label = tk.Label(severity_frame, text=f" {severity} ",
                                  bg=severity_colors.get(severity, '#999999'),
                                  fg='white', font=('Arial', 10, 'bold'))
        severity_label.pack(side=tk.RIGHT)

        # CVSS Score
        cvss_frame = ttk.Frame(header_frame)
        cvss_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(cvss_frame, text="CVSS Score:", font=('Arial', 11, 'bold')).pack(side=tk.LEFT)
        cvss_score = cve_data.get('cvss_score', 'N/A')
        ttk.Label(cvss_frame, text=str(cvss_score), font=('Arial', 11)).pack(side=tk.LEFT, padx=(10, 0))

        # Published date
        date_frame = ttk.Frame(header_frame)
        date_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(date_frame, text="Published:", font=('Arial', 11, 'bold')).pack(side=tk.LEFT)
        ttk.Label(date_frame, text=cve_data.get('published', 'Unknown'),
                  font=('Arial', 11)).pack(side=tk.LEFT, padx=(10, 0))

        # Description
        desc_frame = ttk.LabelFrame(scrollable_frame, text="Description", padding="10")
        desc_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        desc_text = scrolledtext.ScrolledText(desc_frame, wrap=tk.WORD, height=8,
                                              font=('Arial', 10))
        desc_text.pack(fill=tk.BOTH, expand=True)
        desc_text.insert(tk.END, cve_data.get('description', 'No description available'))
        desc_text.configure(state=tk.DISABLED)

        # Affected products
        products_frame = ttk.LabelFrame(scrollable_frame, text="Affected Products", padding="10")
        products_frame.pack(fill=tk.X, pady=(0, 10))

        products = cve_data.get('affected_products', [])
        if products:
            for product in products[:10]:  # Limit to 10 products
                product_label = ttk.Label(products_frame, text=f"• {product}",
                                          font=('Arial', 10))
                product_label.pack(anchor=tk.W, pady=1)

            if len(products) > 10:
                ttk.Label(products_frame, text=f"... and {len(products) - 10} more",
                          font=('Arial', 10, 'italic')).pack(anchor=tk.W, pady=1)
        else:
            ttk.Label(products_frame, text="No specific products listed",
                      font=('Arial', 10, 'italic')).pack(anchor=tk.W)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_technical_tab(self, notebook, cve_data):
        """Create technical details tab"""
        tech_frame = ttk.Frame(notebook)
        notebook.add(tech_frame, text="🔧 Technical")

        # Technical details content
        tech_text = scrolledtext.ScrolledText(tech_frame, wrap=tk.WORD, font=('Consolas', 10))
        tech_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Format technical information
        tech_info = self._format_technical_details(cve_data)
        tech_text.insert(tk.END, tech_info)
        tech_text.configure(state=tk.DISABLED)

    def create_links_tab(self, notebook, cve_data):
        """Create links and resources tab"""
        links_frame = ttk.Frame(notebook)
        notebook.add(links_frame, text="🔗 Resources")

        # Enhanced links using ML validation
        enhanced_cve = self.link_validator.validate_and_fix_cve_links([cve_data])[0]

        # Primary link
        primary_frame = ttk.LabelFrame(links_frame, text="Primary Resource", padding="10")
        primary_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        primary_url = enhanced_cve.get('primary_url', '')
        confidence = enhanced_cve.get('url_confidence', 0)

        if primary_url:
            link_frame = ttk.Frame(primary_frame)
            link_frame.pack(fill=tk.X)

            # Clickable link
            link_label = tk.Label(link_frame, text=primary_url, fg='blue',
                                  cursor='hand2', font=('Arial', 10, 'underline'))
            link_label.pack(side=tk.LEFT)
            link_label.bind("<Button-1>", lambda e: webbrowser.open(primary_url))

            # Confidence indicator
            confidence_text = f"Confidence: {confidence:.1%}"
            confidence_color = '#4caf50' if confidence > 0.7 else '#ff9800' if confidence > 0.4 else '#f44336'

            conf_label = tk.Label(link_frame, text=confidence_text, fg=confidence_color,
                                  font=('Arial', 9, 'bold'))
            conf_label.pack(side=tk.RIGHT)

        # Alternative links
        alt_frame = ttk.LabelFrame(links_frame, text="Alternative Resources", padding="10")
        alt_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        alt_urls = enhanced_cve.get('alternative_urls', [])
        for i, url in enumerate(alt_urls):
            if url != primary_url:  # Don't duplicate primary
                alt_link_frame = ttk.Frame(alt_frame)
                alt_link_frame.pack(fill=tk.X, pady=2)

                # Link number
                ttk.Label(alt_link_frame, text=f"{i + 1}.",
                          font=('Arial', 10, 'bold')).pack(side=tk.LEFT)

                # Clickable link
                alt_link = tk.Label(alt_link_frame, text=url, fg='blue',
                                    cursor='hand2', font=('Arial', 10, 'underline'))
                alt_link.pack(side=tk.LEFT, padx=(5, 0))
                alt_link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

        # Search for additional resources button
        search_frame = ttk.Frame(links_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(search_frame, text="🔍 Find More Resources",
                   command=lambda: self._search_additional_resources(cve_data)).pack()

    def create_mitigation_tab(self, notebook, cve_data):
        """Create mitigation and remediation tab"""
        mitigation_frame = ttk.Frame(notebook)
        notebook.add(mitigation_frame, text="🛡️ Mitigation")

        # Mitigation content
        mitigation_text = scrolledtext.ScrolledText(mitigation_frame, wrap=tk.WORD,
                                                    font=('Arial', 10))
        mitigation_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Generate mitigation advice
        mitigation_info = self._generate_mitigation_advice(cve_data)
        mitigation_text.insert(tk.END, mitigation_info)
        mitigation_text.configure(state=tk.DISABLED)

    def _format_technical_details(self, cve_data):
        """Format technical details for display"""
        details = []

        details.append("=== CVE TECHNICAL DETAILS ===\n")
        details.append(f"CVE ID: {cve_data.get('cve_id', 'Unknown')}\n")
        details.append(f"CVSS v3.1 Base Score: {cve_data.get('cvss_score', 'N/A')}\n")
        details.append(f"Severity: {cve_data.get('severity', 'Unknown')}\n")
        details.append(f"Published: {cve_data.get('published', 'Unknown')}\n")
        details.append(f"Source: {cve_data.get('source', 'Unknown')}\n\n")

        details.append("=== VULNERABILITY DESCRIPTION ===\n")
        details.append(f"{cve_data.get('description', 'No description available')}\n\n")

        details.append("=== AFFECTED PRODUCTS ===\n")
        products = cve_data.get('affected_products', [])
        if products:
            for product in products:
                details.append(f"- {product}\n")
        else:
            details.append("No specific products listed\n")

        details.append("\n=== ADDITIONAL INFORMATION ===\n")
        details.append("This vulnerability information is provided by the National Vulnerability Database (NVD).\n")
        details.append("For the most current information, please refer to the official CVE entry.\n")

        return ''.join(details)

    def _generate_mitigation_advice(self, cve_data):
        """Generate mitigation advice based on CVE data"""
        advice = []

        advice.append("=== GENERAL MITIGATION STRATEGIES ===\n\n")

        severity = cve_data.get('severity', '').lower()
        cvss_score = cve_data.get('cvss_score', 0)

        if severity == 'critical' or cvss_score >= 9.0:
            advice.append("🚨 CRITICAL PRIORITY - Immediate Action Required:\n")
            advice.append("• Apply security patches immediately\n")
            advice.append("• Consider taking affected systems offline if patches unavailable\n")
            advice.append("• Implement emergency network segmentation\n")
            advice.append("• Monitor for signs of exploitation\n\n")

        elif severity == 'high' or cvss_score >= 7.0:
            advice.append("⚠️ HIGH PRIORITY - Urgent Action Required:\n")
            advice.append("• Apply patches within 72 hours\n")
            advice.append("• Increase monitoring of affected systems\n")
            advice.append("• Review access controls\n\n")

        else:
            advice.append("📋 STANDARD PRIORITY:\n")
            advice.append("• Apply patches during next maintenance window\n")
            advice.append("• Include in regular vulnerability management process\n\n")

        advice.append("=== RECOMMENDED ACTIONS ===\n\n")
        advice.append("1. ASSESSMENT:\n")
        advice.append("   • Identify all affected systems in your environment\n")
        advice.append("   • Assess potential impact and exposure\n")
        advice.append("   • Prioritize based on system criticality\n\n")

        advice.append("2. IMMEDIATE STEPS:\n")
        advice.append("   • Check vendor advisories for patches\n")
        advice.append("   • Implement temporary workarounds if available\n")
        advice.append("   • Enhance monitoring and logging\n\n")

        advice.append("3. LONG-TERM MEASURES:\n")
        advice.append("   • Update vulnerability management procedures\n")
        advice.append("   • Review and improve patch management processes\n")
        advice.append("   • Consider security architecture improvements\n\n")

        advice.append("=== MONITORING RECOMMENDATIONS ===\n\n")
        advice.append("• Monitor network traffic for suspicious patterns\n")
        advice.append("• Check system logs for exploitation attempts\n")
        advice.append("• Implement intrusion detection signatures\n")
        advice.append("• Review user access and authentication logs\n\n")

        advice.append("NOTE: This is general guidance. Consult with security professionals\n")
        advice.append("and refer to vendor-specific advisories for detailed mitigation steps.")

        return ''.join(advice)

    def _search_additional_resources(self, cve_data):
        """Search for additional resources using ML techniques"""
        cve_id = cve_data.get('cve_id', '')

        if cve_id:
            # Use ML link validator to find more resources
            additional_links = self.link_validator.smart_search_links(cve_id, 'cve')

            # Show results in a new window
            self._show_search_results(additional_links, cve_id)

    def _show_search_results(self, search_results, query):
        """Show search results in a popup"""
        results_window = tk.Toplevel(self.detail_window)
        results_window.title(f"Additional Resources - {query}")
        results_window.geometry("700x500")

        # Results list
        results_frame = ttk.LabelFrame(results_window, text=f"Search Results for {query}", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollable results
        canvas = tk.Canvas(results_frame)
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        for i, result in enumerate(search_results[:20]):  # Limit to top 20
            result_frame = ttk.Frame(scrollable_frame, relief=tk.RIDGE, borderwidth=1)
            result_frame.pack(fill=tk.X, pady=2, padx=2)

            # Title and link
            title = result.get('title', result.get('url', 'Unknown'))
            link_label = tk.Label(result_frame, text=f"{i + 1}. {title}",
                                  fg='blue', cursor='hand2',
                                  font=('Arial', 10, 'underline'))
            link_label.pack(anchor=tk.W, padx=5, pady=2)

            url = result.get('url', '')
            link_label.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

            # Description and relevance
            desc = result.get('description', '')
            relevance = result.get('relevance_score', 0)

            if desc:
                desc_label = ttk.Label(result_frame, text=desc,
                                       font=('Arial', 9), foreground='gray')
                desc_label.pack(anchor=tk.W, padx=15, pady=(0, 2))

            # Relevance score
            relevance_label = ttk.Label(result_frame,
                                        text=f"Relevance: {relevance:.1%}",
                                        font=('Arial', 8), foreground='green')
            relevance_label.pack(anchor=tk.E, padx=5)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")