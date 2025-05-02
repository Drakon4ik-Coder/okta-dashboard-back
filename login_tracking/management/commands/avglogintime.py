from django.core.management.base import BaseCommand
from django.db.models import Avg
from login_tracking.models import LoginTiming
from django.utils import timezone

class Command(BaseCommand):
    help = "Prints the average response time (in ms) of the login endpoint."

    def add_arguments(self, parser):
        parser.add_argument(
            '--since-days', '-d',
            type=int,
            default=None,
            help="Only include timings from the last N days."
        )

    def handle(self, *args, **options):
        qs = LoginTiming.objects.all()
        if options['since_days'] is not None:
            cutoff = timezone.now() - timezone.timedelta(days=options['since_days'])
            qs = qs.filter(timestamp__gte=cutoff)

        avg = qs.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
        if options['since_days']:
            self.stdout.write(self.style.SUCCESS(
                f"Average login time over last {options['since_days']} days: {avg:.2f} ms"
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"Average login time (all records): {avg:.2f} ms"
            ))
