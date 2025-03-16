from django.db.models.signals import post_migrate
from django.dispatch import receiver

@receiver(post_migrate)
def setup_periodic_tasks(sender, **kwargs):
    """
    Set up scheduled tasks after database migrations complete
    This avoids accessing the database during app initialization
    """
    # Only run for our app
    if sender.name == 'TrafficAnalysis':
        from TrafficAnalysis.schedule import setup_schedules
        setup_schedules()