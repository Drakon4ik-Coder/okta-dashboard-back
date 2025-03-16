from mongoengine import Document, StringField, DateTimeField, DictField, ListField, Q
import datetime

class OktaLog(Document):
    """MongoDB model for Okta logs"""
    event_id = StringField(required=True, unique=True)
    event_type = StringField(required=True)
    published = DateTimeField(required=True)
    actor_id = StringField()
    actor_type = StringField()
    actor_display_name = StringField()
    actor_alternate_id = StringField()
    client_ip = StringField()
    outcome_result = StringField()
    outcome_reason = StringField()
    target = ListField(DictField())
    raw_data = DictField()
    created_at = DateTimeField(default=datetime.datetime.now)
    
    meta = {
        'collection': 'okta_logs',
        'indexes': [
            'event_id',
            'event_type',
            'published', 
            'actor_id',
            'actor_display_name',
            'client_ip',
            'outcome_result'
        ],
        'ordering': ['-published']
    }
    
    @classmethod
    def get_logs(cls, filters=None, start_date=None, end_date=None, limit=100, skip=0):
        """Query logs with optional filtering"""
        query = Q()
        
        if filters:
            for key, value in filters.items():
                if isinstance(value, str) and ('*' in value or '?' in value):
                    # Handle wildcard searches
                    pattern = value.replace('*', '.*').replace('?', '.')
                    query = query & Q(**{f"{key}__regex": pattern})
                else:
                    query = query & Q(**{key: value})
        
        if start_date:
            query = query & Q(published__gte=start_date)
            
        if end_date:
            query = query & Q(published__lte=end_date)
        
        return cls.objects(query).order_by('-published').limit(limit).skip(skip)
