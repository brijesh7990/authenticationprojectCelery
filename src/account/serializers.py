from .models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email")


class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "password2")
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "Passwords must match."})
        return data

    def create(self, validated_data):
        password2 = validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    new_password2 = serializers.CharField()

    def validate(self, data):
        if data["new_password"] != data["new_password2"]:
            raise serializers.ValidationError(
                {"new_password": "New passwords must match."}
            )
        return data


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField()
    new_password2 = serializers.CharField()

    def validate(self, data):
        if data["new_password"] != data["new_password2"]:
            raise serializers.ValidationError(
                {"new_password": "New passwords must match."}
            )
        return data
