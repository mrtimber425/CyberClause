# Engines package initialization
from .base_engine import BaseEngine
from .vulnerabilities_engine import VulnerabilitiesEngine
from .news_engine import NewsEngine
from .cyber_docs_engine import CyberDocsEngine
from .breaches_engine import BreachesEngine

# Legacy engines for backward compatibility
try:
    from .policies_engine import PoliciesEngine
    from .frameworks_engine import FrameworksEngine
    from .documentation_engine import DocumentationEngine
except ImportError:
    # These are now combined into CyberDocsEngine
    pass

__all__ = [
    'BaseEngine',
    'VulnerabilitiesEngine',
    'NewsEngine',
    'CyberDocsEngine',
    'BreachesEngine'
]