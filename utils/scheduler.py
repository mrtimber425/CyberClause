from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import atexit


class DataScheduler:
    def __init__(self, engines_dict):
        self.engines = engines_dict
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

        # Ensure cleanup on exit
        atexit.register(lambda: self.scheduler.shutdown())

        # Schedule initial refresh
        self.schedule_refresh_jobs()

    def schedule_refresh_jobs(self):
        """Schedule automatic refresh jobs for all engines"""

        # Vulnerabilities - every hour for recent CVEs
        self.scheduler.add_job(
            func=self.engines['vulnerabilities'].refresh_data,
            trigger=IntervalTrigger(hours=1),
            id='refresh_vulnerabilities',
            name='Refresh Vulnerabilities',
            replace_existing=True
        )

        # News - every 15 minutes for real-time threat intelligence
        self.scheduler.add_job(
            func=self.engines['news'].refresh_data,
            trigger=IntervalTrigger(minutes=15),
            id='refresh_news',
            name='Refresh News',
            replace_existing=True
        )

        # Cyber Documents (combined policies, frameworks, documentation) - every 6 hours
        self.scheduler.add_job(
            func=self.engines['cyber_docs'].refresh_data,
            trigger=IntervalTrigger(hours=6),
            id='refresh_cyber_docs',
            name='Refresh Cyber Documents',
            replace_existing=True
        )

        # Breaches - every 30 minutes for timely breach detection
        self.scheduler.add_job(
            func=self.engines['breaches'].refresh_data,
            trigger=IntervalTrigger(minutes=30),
            id='refresh_breaches',
            name='Refresh Breaches',
            replace_existing=True
        )

        # Cache cleanup - every hour
        self.scheduler.add_job(
            func=self._cleanup_cache,
            trigger=IntervalTrigger(hours=1),
            id='cleanup_cache',
            name='Cleanup Cache',
            replace_existing=True
        )

        # Daily vulnerability statistics update - once per day
        self.scheduler.add_job(
            func=self._update_vulnerability_stats,
            trigger=IntervalTrigger(hours=24),
            id='update_vuln_stats',
            name='Update Vulnerability Statistics',
            replace_existing=True
        )

        # Weekly bulk data maintenance - once per week
        self.scheduler.add_job(
            func=self._weekly_maintenance,
            trigger=IntervalTrigger(weeks=1),
            id='weekly_maintenance',
            name='Weekly Data Maintenance',
            replace_existing=True
        )

        print("Scheduled refresh jobs for all engines")

    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        try:
            # Get storage from any engine (they all share the same storage)
            storage = list(self.engines.values())[0].storage
            storage.cleanup_expired_cache()
            print("Cache cleanup completed")
        except Exception as e:
            print(f"Error during cache cleanup: {e}")

    def _update_vulnerability_stats(self):
        """Update vulnerability statistics daily"""
        try:
            vuln_engine = self.engines.get('vulnerabilities')
            if vuln_engine:
                stats = vuln_engine.get_statistics()
                print(f"Vulnerability stats updated: {stats['total_cves']} total CVEs")
        except Exception as e:
            print(f"Error updating vulnerability stats: {e}")

    def _weekly_maintenance(self):
        """Perform weekly maintenance tasks"""
        try:
            print("Starting weekly maintenance...")

            # Clean up old data (older than 6 months for some tables)
            storage = list(self.engines.values())[0].storage

            # This would typically include:
            # - Archiving old news articles
            # - Cleaning up duplicate entries
            # - Optimizing database indexes
            # - Generating summary statistics

            print("Weekly maintenance completed")
        except Exception as e:
            print(f"Error during weekly maintenance: {e}")

    def refresh_all(self):
        """Manually refresh all engines"""
        print("Manual refresh started for all engines...")

        refresh_results = {}

        for name, engine in self.engines.items():
            try:
                print(f"Refreshing {name}...")
                result = engine.refresh_data()
                refresh_results[name] = result

                if result:
                    print(f"✅ {name} refreshed successfully")
                else:
                    print(f"❌ {name} refresh failed")

            except Exception as e:
                print(f"❌ Error refreshing {name}: {e}")
                refresh_results[name] = False

        # Print summary
        successful = sum(1 for result in refresh_results.values() if result)
        total = len(refresh_results)

        print(f"Manual refresh completed: {successful}/{total} engines successful")
        return refresh_results

    def refresh_engine(self, engine_name: str):
        """Refresh a specific engine"""
        if engine_name in self.engines:
            try:
                print(f"Refreshing {engine_name}...")
                result = self.engines[engine_name].refresh_data()

                if result:
                    print(f"✅ {engine_name} refreshed successfully")
                else:
                    print(f"❌ {engine_name} refresh failed")

                return result
            except Exception as e:
                print(f"❌ Error refreshing {engine_name}: {e}")
                return False
        else:
            print(f"❌ Engine '{engine_name}' not found")
            return False

    def get_job_status(self):
        """Get status of all scheduled jobs"""
        jobs = []

        for job in self.scheduler.get_jobs():
            next_run = job.next_run_time

            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run': next_run.isoformat() if next_run else None,
                'next_run_human': self._format_next_run(next_run) if next_run else 'Not scheduled'
            })

        return jobs

    def _format_next_run(self, next_run_time):
        """Format next run time in human-readable format"""
        if not next_run_time:
            return 'Not scheduled'

        now = datetime.now(next_run_time.tzinfo)
        diff = next_run_time - now

        if diff.total_seconds() < 60:
            return 'Less than 1 minute'
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() / 60)
            return f'In {minutes} minute{"s" if minutes != 1 else ""}'
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f'In {hours} hour{"s" if hours != 1 else ""}'
        else:
            days = int(diff.total_seconds() / 86400)
            return f'In {days} day{"s" if days != 1 else ""}'

    def pause_jobs(self):
        """Pause all scheduled jobs"""
        try:
            self.scheduler.pause()
            print("All scheduled jobs paused")
            return True
        except Exception as e:
            print(f"Error pausing jobs: {e}")
            return False

    def resume_jobs(self):
        """Resume all scheduled jobs"""
        try:
            self.scheduler.resume()
            print("All scheduled jobs resumed")
            return True
        except Exception as e:
            print(f"Error resuming jobs: {e}")
            return False

    def update_job_interval(self, job_id: str, new_interval_minutes: int):
        """Update the interval for a specific job"""
        try:
            job = self.scheduler.get_job(job_id)
            if job:
                # Remove old job
                self.scheduler.remove_job(job_id)

                # Add new job with updated interval
                if job_id == 'refresh_vulnerabilities':
                    self.scheduler.add_job(
                        func=self.engines['vulnerabilities'].refresh_data,
                        trigger=IntervalTrigger(minutes=new_interval_minutes),
                        id=job_id,
                        name=job.name,
                        replace_existing=True
                    )
                elif job_id == 'refresh_news':
                    self.scheduler.add_job(
                        func=self.engines['news'].refresh_data,
                        trigger=IntervalTrigger(minutes=new_interval_minutes),
                        id=job_id,
                        name=job.name,
                        replace_existing=True
                    )
                elif job_id == 'refresh_cyber_docs':
                    self.scheduler.add_job(
                        func=self.engines['cyber_docs'].refresh_data,
                        trigger=IntervalTrigger(minutes=new_interval_minutes),
                        id=job_id,
                        name=job.name,
                        replace_existing=True
                    )
                elif job_id == 'refresh_breaches':
                    self.scheduler.add_job(
                        func=self.engines['breaches'].refresh_data,
                        trigger=IntervalTrigger(minutes=new_interval_minutes),
                        id=job_id,
                        name=job.name,
                        replace_existing=True
                    )

                print(f"Updated {job_id} interval to {new_interval_minutes} minutes")
                return True
            else:
                print(f"Job {job_id} not found")
                return False

        except Exception as e:
            print(f"Error updating job interval: {e}")
            return False

    def get_engine_status(self):
        """Get status of all engines"""
        status = {}

        for name, engine in self.engines.items():
            try:
                last_refresh = getattr(engine, 'last_refresh', None)
                needs_refresh = getattr(engine, 'needs_refresh', lambda: False)()

                # Get engine-specific statistics if available
                stats = {}
                if hasattr(engine, 'get_statistics'):
                    stats = engine.get_statistics()
                elif hasattr(engine, 'get_news_statistics'):
                    stats = engine.get_news_statistics()
                elif hasattr(engine, 'get_breach_statistics'):
                    stats = engine.get_breach_statistics()
                elif hasattr(engine, 'get_document_statistics'):
                    stats = engine.get_document_statistics()

                status[name] = {
                    'last_refresh': last_refresh.isoformat() if last_refresh else None,
                    'needs_refresh': needs_refresh,
                    'status': 'Active',
                    'statistics': stats
                }

            except Exception as e:
                status[name] = {
                    'last_refresh': None,
                    'needs_refresh': True,
                    'status': f'Error: {str(e)}',
                    'statistics': {}
                }

        return status

    def shutdown(self):
        """Shutdown the scheduler"""
        try:
            self.scheduler.shutdown(wait=False)
            print("Scheduler shutdown completed")
        except Exception as e:
            print(f"Error during scheduler shutdown: {e}")