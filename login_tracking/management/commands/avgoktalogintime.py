from django.core.management.base import BaseCommand
from login_tracking.utils import compute_avg_okta_login_time

class Command(BaseCommand):
    help = "Compute average login time from OktaEvent logs."

    def add_arguments(self, parser):
        parser.add_argument("-d", "--days", type=int, default=1,
                            help="Days to look back")

    def handle(self, *args, **opts):
        avg = compute_avg_okta_login_time(opts["days"])
        if avg is None:
            self.stdout.write(self.style.WARNING("No login events found."))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"Avg login time over last {opts['days']} day(s): {avg:.1f} ms"
            ))
