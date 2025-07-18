from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime, timedelta


class BaseEngine(ABC):
    def __init__(self, storage, api_manager):
        self.storage = storage
        self.api_manager = api_manager
        self.last_refresh = None
        self.refresh_interval = timedelta(hours=1)  # Default refresh interval

    @abstractmethod
    def refresh_data(self) -> bool:
        """Refresh data from external sources"""
        pass

    @abstractmethod
    def get_data(self, filters: Dict = None) -> List[Dict]:
        """Get data with optional filtering"""
        pass

    @abstractmethod
    def search(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search data with query and filters"""
        pass

    def needs_refresh(self) -> bool:
        """Check if data needs to be refreshed"""
        if self.last_refresh is None:
            return True
        return datetime.now() - self.last_refresh > self.refresh_interval

    def filter_data(self, data: List[Dict], filters: Dict) -> List[Dict]:
        """Apply filters to data"""
        if not filters:
            return data

        filtered_data = data.copy()

        # Apply each filter
        for filter_key, filter_value in filters.items():
            if not filter_value:  # Skip empty filters
                continue

            if filter_key == 'search':
                # Text search across all fields
                filtered_data = [
                    item for item in filtered_data
                    if self._text_search(item, filter_value)
                ]
            elif filter_key == 'category':
                filtered_data = [
                    item for item in filtered_data
                    if item.get('category', '').lower() == filter_value.lower()
                ]
            elif filter_key == 'severity':
                filtered_data = [
                    item for item in filtered_data
                    if item.get('severity', '').lower() == filter_value.lower()
                ]
            elif filter_key == 'source':
                filtered_data = [
                    item for item in filtered_data
                    if item.get('source', '').lower() == filter_value.lower()
                ]
            elif filter_key == 'date_range':
                # Filter by date range
                start_date, end_date = filter_value
                filtered_data = [
                    item for item in filtered_data
                    if self._date_in_range(item.get('published', ''), start_date, end_date)
                ]

        return filtered_data

    def _text_search(self, item: Dict, query: str) -> bool:
        """Search for query in item text fields"""
        query = query.lower()
        searchable_fields = ['title', 'description', 'name', 'organization', 'cve_id']

        for field in searchable_fields:
            if field in item and query in str(item[field]).lower():
                return True
        return False

    def _date_in_range(self, date_str: str, start_date: str, end_date: str) -> bool:
        """Check if date is within range"""
        try:
            item_date = datetime.strptime(date_str[:10], '%Y-%m-%d')
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            return start <= item_date <= end
        except:
            return True  # Include items with invalid dates