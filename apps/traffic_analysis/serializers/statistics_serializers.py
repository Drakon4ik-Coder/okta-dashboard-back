from rest_framework import serializers

class StatisticsSerializer(serializers.Serializer):
    """
    Serializer for device and application statistics
    """
    days = serializers.IntegerField(default=30)

class DeviceStatisticsSerializer(serializers.Serializer):
    """
    Serializer for device statistics
    """
    devices = serializers.DictField(child=serializers.IntegerField())

class ApplicationStatisticsSerializer(serializers.Serializer):
    """
    Serializer for application statistics
    """
    applications = serializers.DictField(child=serializers.IntegerField())

class BrowserStatisticsSerializer(serializers.Serializer):
    """
    Serializer for browser statistics
    """
    browsers = serializers.DictField(child=serializers.IntegerField())

class OSStatisticsSerializer(serializers.Serializer):
    """
    Serializer for operating system statistics
    """
    operating_systems = serializers.DictField(child=serializers.IntegerField())

class LocationStatisticsSerializer(serializers.Serializer):
    """
    Serializer for location statistics
    """
    locations = serializers.DictField(child=serializers.IntegerField())

class OutcomeStatisticsSerializer(serializers.Serializer):
    """
    Serializer for login outcome statistics
    """
    outcomes = serializers.DictField()

class AllStatisticsSerializer(serializers.Serializer):
    """
    Serializer for all statistics
    """
    devices = serializers.DictField(child=serializers.IntegerField())
    operating_systems = serializers.DictField(child=serializers.IntegerField())
    browsers = serializers.DictField(child=serializers.IntegerField())
    applications = serializers.DictField(child=serializers.IntegerField())
    locations = serializers.DictField(child=serializers.IntegerField())
    outcomes = serializers.DictField()