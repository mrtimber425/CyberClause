import json
import csv
import os
import sys
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from utils.data_storage import DataStorage


class DataExporter:
    def __init__(self, storage_path=None):
        self.storage_path = storage_path or Config.DATABASE_PATH
        self.storage = DataStorage(self.storage_path)
        self.export_dir = 'exports'
        os.makedirs(self.export_dir, exist_ok=True)

    def export_vulnerabilities(self, format='json'):
        """Export vulnerabilities data"""
        data = self.storage.get_data('vulnerabilities')
        filename = f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if format.lower() == 'json':
            filepath = os.path.join(self.export_dir, f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        elif format.lower() == 'csv':
            filepath = os.path.join(self.export_dir, f"{filename}.csv")
            if data:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    for item in data:
                        # Flatten complex fields
                        flattened = {}
                        for k, v in item.items():
                            if isinstance(v, list):
                                flattened[k] = '; '.join(str(x) for x in v)
                            else:
                                flattened[k] = v
                        writer.writerow(flattened)

        print(f"✅ Vulnerabilities exported to: {filepath}")
        return filepath

    def export_news(self, format='json'):
        """Export news data"""
        data = self.storage.get_data('news')
        filename = f"news_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if format.lower() == 'json':
            filepath = os.path.join(self.export_dir, f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        elif format.lower() == 'csv':
            filepath = os.path.join(self.export_dir, f"{filename}.csv")
            if data:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)

        print(f"✅ News exported to: {filepath}")
        return filepath

    def export_all(self, format='json'):
        """Export all data"""
        print(f"📤 Exporting all data in {format.upper()} format...")

        exports = []
        tables = ['vulnerabilities', 'news', 'policies', 'frameworks', 'documentation']

        for table in tables:
            try:
                data = self.storage.get_data(table)
                if data:
                    filename = f"{table}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

                    if format.lower() == 'json':
                        filepath = os.path.join(self.export_dir, f"{filename}.json")
                        with open(filepath, 'w') as f:
                            json.dump(data, f, indent=2)
                    elif format.lower() == 'csv':
                        filepath = os.path.join(self.export_dir, f"{filename}.csv")
                        with open(filepath, 'w', newline='') as f:
                            if data:
                                # Flatten complex fields for CSV
                                flattened_data = []
                                for item in data:
                                    flattened = {}
                                    for k, v in item.items():
                                        if isinstance(v, list):
                                            flattened[k] = '; '.join(str(x) for x in v)
                                        else:
                                            flattened[k] = v
                                    flattened_data.append(flattened)

                                if flattened_data:
                                    writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
                                    writer.writeheader()
                                    writer.writerows(flattened_data)

                    exports.append(filepath)
                    print(f"✅ {table.title()} exported to: {filepath}")
                else:
                    print(f"⚠️  No data found for {table}")
            except Exception as e:
                print(f"❌ Error exporting {table}: {e}")

        print(f"\n🎉 Export complete! {len(exports)} files created in '{self.export_dir}' directory")
        return exports

    def create_summary_report(self):
        """Create a summary report of all data"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(self.export_dir, f"summary_report_{timestamp}.txt")

        with open(report_path, 'w') as f:
            f.write("CYBERSEC DASHBOARD DATA SUMMARY REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            tables = ['vulnerabilities', 'news', 'policies', 'frameworks', 'documentation']

            for table in tables:
                try:
                    data = self.storage.get_data(table)
                    f.write(f"{table.upper()}:\n")
                    f.write(f"  Total Records: {len(data)}\n")

                    if data:
                        # Sample data analysis
                        if table == 'vulnerabilities':
                            severities = {}
                            for item in data:
                                sev = item.get('severity', 'Unknown')
                                severities[sev] = severities.get(sev, 0) + 1
                            f.write(f"  Severity Breakdown: {severities}\n")

                        elif table == 'news':
                            categories = {}
                            sources = {}
                            for item in data:
                                cat = item.get('category', 'Unknown')
                                src = item.get('source', 'Unknown')
                                categories[cat] = categories.get(cat, 0) + 1
                                sources[src] = sources.get(src, 0) + 1
                            f.write(f"  Top Categories: {dict(list(categories.items())[:5])}\n")
                            f.write(f"  Top Sources: {dict(list(sources.items())[:5])}\n")

                    f.write("\n")
                except Exception as e:
                    f.write(f"  Error: {e}\n\n")

        print(f"📊 Summary report created: {report_path}")
        return report_path


if __name__ == '__main__':
    exporter = DataExporter()

    # Check command line arguments
    if len(sys.argv) > 1:
        format_type = sys.argv[1].lower()
        if format_type in ['json', 'csv']:
            exporter.export_all(format_type)
        else:
            print("Usage: python data_export.py [json|csv]")
    else:
        # Default to JSON export
        exporter.export_all('json')

    # Always create summary report
    exporter.create_summary_report()