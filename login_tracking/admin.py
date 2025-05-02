from django.contrib import admin
from .models import LoginTiming

@admin.register(LoginTiming)
class LoginTimingAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'duration_ms')
    list_filter = ('timestamp',)
    ordering = ('-timestamp',)
