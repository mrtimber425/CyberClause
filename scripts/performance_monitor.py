import psutil
import time
import json
from datetime import datetime
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from utils.data_storage import DataStorage


class PerformanceMonitor:
    def __init__(self, storage_path=None):
        self.storage_path = storage_path or Config.DATABASE_PATH
        self.storage = DataStorage(self.storage_path) if os.path.exists(self.storage_path) else None
        self.metrics = []

    def collect_system_metrics(self):
        """Collect system performance metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used_mb': memory.used / (1024 * 1024),
            'memory_available_mb': memory.available / (1024 * 1024),
            'disk_percent': disk.percent,
            'disk_used_gb': disk.used / (1024 * 1024 * 1024),
            'disk_free_gb': disk.free / (1024 * 1024 * 1024)
        }

        return metrics

    def collect_database_metrics(self):
        """Collect database performance metrics"""
        if not self.storage:
            return {}

        try:
            # Count records in each table
            vuln_count = len(self.storage.get_data('vulnerabilities'))
            news_count = len(self.storage.get_data('news'))
            policies_count = len(self.storage.get_data('policies'))
            frameworks_count = len(self.storage.get_data('frameworks'))

            # Get database file size
            db_size = os.path.getsize(self.storage_path) / (1024 * 1024)  # MB

            return {
                'vulnerabilities_count': vuln_count,
                'news_count': news_count,
                'policies_count': policies_count,
                'frameworks_count': frameworks_count,
                'database_size_mb': db_size
            }
        except Exception as e:
            print(f"Error collecting database metrics: {e}")
            return {}

    def generate_report(self, duration_minutes=5, interval_seconds=30):
        """Generate a performance report over specified duration"""
        print(f"🔍 Monitoring performance for {duration_minutes} minutes...")

        end_time = time.time() + (duration_minutes * 60)

        while time.time() < end_time:
            system_metrics = self.collect_system_metrics()
            db_metrics = self.collect_database_metrics()

            combined_metrics = {**system_metrics, **db_metrics}
            self.metrics.append(combined_metrics)

            print(f"CPU: {system_metrics['cpu_percent']:.1f}% | "
                  f"Memory: {system_metrics['memory_percent']:.1f}% | "
                  f"DB Size: {db_metrics.get('database_size_mb', 0):.1f}MB")

            time.sleep(interval_seconds)

        # Generate summary report
        self.save_report()
        self.print_summary()

    def save_report(self):
        """Save performance report to file"""
        report_file = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        summary = {
            'collection_period': {
                'start': self.metrics[0]['timestamp'] if self.metrics else None,
                'end': self.metrics[-1]['timestamp'] if self.metrics else None,
                'samples': len(self.metrics)
            },
            'metrics': self.metrics,
            'averages': self.calculate_averages()
        }

        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"📊 Performance report saved to: {report_file}")

    def calculate_averages(self):
        """Calculate average metrics"""
        if not self.metrics:
            return {}

        numeric_fields = ['cpu_percent', 'memory_percent', 'memory_used_mb',
                          'disk_percent', 'database_size_mb']

        averages = {}
        for field in numeric_fields:
            values = [m.get(field, 0) for m in self.metrics if field in m]
            if values:
                averages[f'avg_{field}'] = sum(values) / len(values)
                averages[f'max_{field}'] = max(values)
                averages[f'min_{field}'] = min(values)

        return averages

    def print_summary(self):
        """Print performance summary"""
        if not self.metrics:
            print("No metrics collected")
            return

        averages = self.calculate_averages()

        print("\n📈 PERFORMANCE SUMMARY")
        print("=" * 50)
        print(f"CPU Usage: Avg {averages.get('avg_cpu_percent', 0):.1f}% | "
              f"Max {averages.get('max_cpu_percent', 0):.1f}%")
        print(f"Memory Usage: Avg {averages.get('avg_memory_percent', 0):.1f}% | "
              f"Max {averages.get('max_memory_percent', 0):.1f}%")
        print(f"Database Size: {averages.get('avg_database_size_mb', 0):.1f}MB")

        # Check for performance issues
        if averages.get('avg_cpu_percent', 0) > 80:
            print("⚠️  HIGH CPU USAGE DETECTED")
        if averages.get('avg_memory_percent', 0) > 80:
            print("⚠️  HIGH MEMORY USAGE DETECTED")

        print("=" * 50)


if __name__ == '__main__':
    monitor = PerformanceMonitor()
    monitor.generate_report(duration_minutes=2, interval_seconds=10)