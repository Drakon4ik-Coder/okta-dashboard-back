from django.db import models

class LoginTiming(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    duration_ms = models.FloatField(help_text='Response time in milliseconds')

    def __str__(self):
        ts = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"{self.duration_ms:.2f} ms @ {ts}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Login timing'
        verbose_name_plural = 'Login timings'
