from rest_framework import serializers
from .models import Users  # Adjust the import according to your project structure

# User Serializer
class UsersSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=False)
    class Meta:
        model = Users
        fields = '__all__'


# Retrieve User Serializer
class GetUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=False)
    class Meta:
        model = Users
        exclude = ('password',)
