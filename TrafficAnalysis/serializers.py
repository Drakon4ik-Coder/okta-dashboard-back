from rest_framework import serializers

class OktaLogSerializer(serializers.Serializer):
    """Serializer for Okta logs"""
    event_id = serializers.CharField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    published = serializers.DateTimeField(read_only=True)
    actor_id = serializers.CharField(read_only=True)
    actor_type = serializers.CharField(read_only=True)
    actor_display_name = serializers.CharField(read_only=True)
    actor_alternate_id = serializers.CharField(read_only=True)
    client_ip = serializers.CharField(read_only=True)
    outcome_result = serializers.CharField(read_only=True)
    outcome_reason = serializers.CharField(read_only=True)
    target = serializers.ListField(child=serializers.DictField(), read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

class OktaLogDetailSerializer(OktaLogSerializer):
    """Detailed serializer for Okta logs including raw data"""
    raw_data = serializers.DictField(read_only=True)