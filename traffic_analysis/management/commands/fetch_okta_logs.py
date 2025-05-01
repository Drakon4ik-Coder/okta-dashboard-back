import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from OktaDashboardBackend.services.okta_client import OktaApiClient
from OktaDashboardBackend.services.okta_oauth import OktaOAuthClient
from traffic_analysis.models import OktaEvent

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Fetches Okta logs and stores them in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--minutes',
            type=int,
            default=5,
            help='Fetch logs from the last N minutes'
        )
        parser.add_argument(
            '--use-oauth',
            action='store_true',
            default=True,
            help='Use OAuth 2.0 with short-lived tokens instead of API tokens'
        )

    def handle(self, *args, **options):
        minutes = options['minutes']
        use_oauth = options['use_oauth']
        
        self.stdout.write(f"Fetching Okta logs from the last {minutes} minutes...")
        self.stdout.write(f"Authentication method: {'OAuth 2.0' if use_oauth else 'API Token'}")
        
        # Calculate the time range
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        try:
            # Get authentication token using the preferred method
            if use_oauth:
                self.stdout.write("Using OAuth 2.0 for authentication (zero-trust approach)...")
                token = self._get_oauth_token()
            else:
                self.stdout.write("Using API token for authentication...")
                token = None  # OktaApiClient will use the API token from settings
            
            # Initialize the Okta API client with the appropriate token
            okta_client = OktaApiClient(oauth_token=token if use_oauth else None)
            
            # Get security events from Okta
            self.stdout.write("Retrieving security events from Okta API...")
            events = okta_client.get_security_events(
                since=start_time,
                until=end_time,
                cache_timeout=0  # Don't cache this request
            )
            
            if not events:
                self.stdout.write(self.style.WARNING("No events found in the specified timeframe"))
                return
            
            # Process and store each event
            saved_count = 0
            for event in events:
                try:
                    # Check if event already exists in database
                    event_id = event.get('uuid', event.get('id'))
                    
                    if not event_id:
                        logger.warning("Event without ID found, skipping")
                        continue
                    
                    # Try to find existing event
                    existing = OktaEvent.objects.filter(event_id=event_id).first()
                    
                    if existing:
                        logger.debug(f"Event {event_id} already exists, skipping")
                        continue
                    
                    # Create new event object
                    okta_event = OktaEvent(
                        event_id=event_id,
                        event_type=event.get('eventType'),
                        severity=event.get('severity', 'INFO'),
                        display_message=event.get('displayMessage'),
                        published=event.get('published'),
                        actor=event.get('actor'),
                        client=event.get('client'),
                        device=event.get('device'),
                        outcome=event.get('outcome'),
                        target=event.get('target'),
                        ip_address=event.get('client', {}).get('ipAddress'),
                        user_id=event.get('actor', {}).get('id'),
                        username=event.get('actor', {}).get('displayName'),
                        raw_data=event
                    )
                    
                    # Save to MongoDB
                    okta_event.save()
                    saved_count += 1
                
                except Exception as e:
                    logger.error(f"Error saving event: {str(e)}")
            
            # Report results
            self.stdout.write(
                self.style.SUCCESS(f"Successfully processed {len(events)} events, saved {saved_count} new events")
            )
        
        except Exception as e:
            error_msg = f"Error fetching Okta logs: {str(e)}"
            logger.error(error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
    
    def _get_oauth_token(self):
        """
        Get a short-lived OAuth token for authentication - preferred in zero-trust architecture.
        This method uses client credentials flow to get an OAuth token.
        """
        try:
            oauth_client = OktaOAuthClient()
            # Using client credentials flow - suitable for server-to-server communications
            token_response = oauth_client.get_client_credentials_token()
            logger.info("Successfully obtained OAuth token for Okta API access")
            return token_response.get('access_token')
        except Exception as e:
            logger.error(f"Failed to get OAuth token: {e}")
            raise