import os
import sys
import sqlite3
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from utils.data_storage import DataStorage


class DatabaseMaintenance:
    def __init__(self, storage_path=None):
        self.storage_path = storage_path or Config.DATABASE_PATH
        self.storage = DataStorage(self.storage_path)

    def vacuum_database(self):
        """Vacuum the database to reclaim space"""
        print("🧹 Vacuuming database...")
        try:
            conn = sqlite3.connect(self.storage_path)
            conn.execute('VACUUM')
            conn.close()
            print("✅ Database vacuumed successfully")
        except Exception as e:
            print(f"❌ Error vacuuming database: {e}")

    def analyze_database(self):
        """Analyze database tables for optimization"""
        print("📊 Analyzing database...")
        try:
            conn = sqlite3.connect(self.storage_path)
            conn.execute('ANALYZE')
            conn.close()
            print("✅ Database analyzed successfully")
        except Exception as e:
            print(f"❌ Error analyzing database: {e}")

    def cleanup_old_cache(self, days_old=7):
        """Clean up cache entries older than specified days"""
        print(f"🗑️  Cleaning up cache entries older than {days_old} days...")
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.execute(
                'DELETE FROM cache WHERE expires_at < ?',
                (cutoff_date,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            print(f"✅ Deleted {deleted_count} expired cache entries")
        except Exception as e:
            print(f"❌ Error cleaning cache: {e}")

    def cleanup_old_data(self, table, days_old=30):
        """Clean up old data from specified table"""
        print(f"🗑️  Cleaning up {table} data older than {days_old} days...")
        try:
            cutoff_date = (datetime.now() - timedelta(days=days_old)).isoformat()
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.execute(
                f'DELETE FROM {table} WHERE last_updated < ?',
                (cutoff_date,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            print(f"✅ Deleted {deleted_count} old {table} records")
        except Exception as e:
            print(f"❌ Error cleaning {table}: {e}")

    def get_database_stats(self):
        """Get database statistics"""
        print("📈 Database Statistics:")
        print("=" * 40)

        try:
            # File size
            size_mb = os.path.getsize(self.storage_path) / (1024 * 1024)
            print(f"Database Size: {size_mb:.2f} MB")

            # Table counts
            tables = ['vulnerabilities', 'news', 'policies', 'frameworks', 'documentation', 'cache']

            conn = sqlite3.connect(self.storage_path)
            for table in tables:
                try:
                    cursor = conn.execute(f'SELECT COUNT(*) FROM {table}')
                    count = cursor.fetchone()[0]
                    print(f"{table.title()}: {count} records")
                except sqlite3.OperationalError:
                    print(f"{table.title()}: Table not found")

            # Cache statistics
            try:
                cursor = conn.execute('SELECT COUNT(*) FROM cache WHERE expires_at > ?', (datetime.now(),))
                active_cache = cursor.fetchone()[0]
                cursor = conn.execute('SELECT COUNT(*) FROM cache WHERE expires_at <= ?', (datetime.now(),))
                expired_cache = cursor.fetchone()[0]
                print(f"Active Cache: {active_cache} entries")
                print(f"Expired Cache: {expired_cache} entries")
            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception as e:
            print(f"❌ Error getting database stats: {e}")

        print("=" * 40)

    def backup_database(self):
        """Create a backup of the database"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{self.storage_path}.backup_{timestamp}"

        print(f"💾 Creating database backup...")
        try:
            # Copy database file
            import shutil
            shutil.copy2(self.storage_path, backup_path)
            print(f"✅ Backup created: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"❌ Error creating backup: {e}")
            return None

    def run_full_maintenance(self):
        """Run complete database maintenance"""
        print("🔧 Starting Full Database Maintenance")
        print("=" * 50)

        # Create backup first
        backup_path = self.backup_database()

        if backup_path:
            # Get initial stats
            print("\nBEFORE MAINTENANCE:")
            self.get_database_stats()

            # Run maintenance tasks
            self.cleanup_old_cache(days_old=1)  # Clean cache older than 1 day
            self.cleanup_old_data('vulnerabilities', days_old=30)  # Keep 30 days of vulnerabilities
            self.cleanup_old_data('news', days_old=14)  # Keep 14 days of news
            self.vacuum_database()
            self.analyze_database()

            # Get final stats
            print("\nAFTER MAINTENANCE:")
            self.get_database_stats()

            print("\n🎉 Database maintenance completed!")
        else:
            print("❌ Maintenance aborted due to backup failure")


if __name__ == '__main__':
    maintenance = DatabaseMaintenance()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == 'stats':
            maintenance.get_database_stats()
        elif command == 'backup':
            maintenance.backup_database()
        elif command == 'vacuum':
            maintenance.vacuum_database()
        elif command == 'cleanup':
            maintenance.cleanup_old_cache()
        elif command == 'full':
            maintenance.run_full_maintenance()
        else:
            print("Usage: python database_maintenance.py [stats|backup|vacuum|cleanup|full]")
    else:
        maintenance.run_full_maintenance()