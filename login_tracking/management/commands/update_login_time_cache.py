from django.core.management.base import BaseCommand
from login_tracking.metrics import calculate_and_cache_avg_login_time

class Command(BaseCommand):
    help = "Updates the cached average login time value"

    def handle(self, *args, **options):
        avg_ms = calculate_and_cache_avg_login_time()
        self.stdout.write(self.style.SUCCESS(
            f"Updated cached average login time: {avg_ms:.2f} ms"
        ))