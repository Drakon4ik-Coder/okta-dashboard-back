import logging
import argparse
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from OktaDashboardBackend.services.okta_logs import OktaLogsClient

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Fetches Okta logs using DPoP authentication and stores them in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=0,
            help='Fetch logs from the last N days'
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=0,
            help='Fetch logs from the last N hours'
        )
        parser.add_argument(
            '--minutes',
            type=int,
            default=15,
            help='Fetch logs from the last N minutes'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of logs to fetch per request'
        )
        parser.add_argument(
            '--filter',
            type=str,
            help='Filter query for Okta logs (e.g. "eventType eq \"user.session.start\"")'
        )
        parser.add_argument(
            '--direct-mongo',
            action='store_true',
            default=False,
            help='Use direct MongoDB connection instead of DatabaseService'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help='Only fetch logs, do not store them in the database'
        )

    def handle(self, *args, **options):
        days = options['days']
        hours = options['hours']
        minutes = options['minutes']
        limit = options['limit']
        filter_query = options.get('filter')
        use_direct_mongo = options['direct_mongo']
        dry_run = options['dry_run']
        
        # Calculate total minutes
        total_minutes = days * 24 * 60 + hours * 60 + minutes
        if total_minutes <= 0:
            total_minutes = 15  # Default to 15 minutes
        
        self.stdout.write(f"Fetching Okta logs from the last {total_minutes} minutes...")
        
        # Calculate the time range for the filter
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=total_minutes)
        
        # Format times for Okta's filter format (ISO 8601)
        start_time_str = start_time.isoformat() + 'Z'
        end_time_str = end_time.isoformat() + 'Z'
        
        try:
            # Initialize the Okta Logs Client with appropriate settings
            self.stdout.write(f"Initializing OktaLogsClient with direct MongoDB connection: {use_direct_mongo}")
            logs_client = OktaLogsClient(use_direct_mongodb=use_direct_mongo)
            
            # Build the query parameters
            params = {
                "limit": limit,
                "filter": f"published gt \"{start_time_str}\"" + (f" and {filter_query}" if filter_query else "")
            }
            
            self.stdout.write(f"Query parameters: {params}")
            
            # Fetch logs from Okta
            self.stdout.write("Retrieving logs from Okta API...")
            logs = logs_client.get_logs(
                params=params, 
                retry_on_error=True,
                store_in_mongodb=(not dry_run)
            )
            
            if not logs:
                self.stdout.write(self.style.WARNING("No logs found in the specified timeframe"))
                return
            
            # Report results
            self.stdout.write(
                self.style.SUCCESS(f"Successfully retrieved {len(logs)} logs from Okta")
            )
            
            if dry_run:
                self.stdout.write(self.style.WARNING("Dry run mode: logs were not stored in MongoDB"))
            else:
                self.stdout.write(self.style.SUCCESS("Logs were stored in MongoDB"))
            
            # Provide a sample of the first log
            if logs:
                self.stdout.write("\nSample log entry:")
                sample_log = logs[0]
                sample_display = {
                    "uuid": sample_log.get("uuid"),
                    "eventType": sample_log.get("eventType"),
                    "severity": sample_log.get("severity"),
                    "displayMessage": sample_log.get("displayMessage"),
                    "published": sample_log.get("published"),
                    "outcome": sample_log.get("outcome"),
                }
                for key, value in sample_display.items():
                    self.stdout.write(f"  {key}: {value}")
        
        except Exception as e:
            error_msg = f"Error fetching Okta logs: {str(e)}"
            logger.error(error_msg)
            self.stdout.write(self.style.ERROR(error_msg))