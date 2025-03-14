from rest_framework import serializers


# Base serializer example
class BaseModelSerializer(serializers.ModelSerializer):
    """
    Base serializer with common methods.
    """

    class Meta:
        # Override these in child classes
        model = None
        fields = '__all__'

    def validate(self, data):
        """
        Add custom validation logic here.
        """
        return data


# Example serializer for a hypothetical model
class BaseReadOnlySerializer(serializers.Serializer):
    """
    A read-only serializer for displaying data.
    """
    id = serializers.IntegerField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    def to_representation(self, instance):
        """
        Custom representation logic can go here.
        """
        return super().to_representation(instance)