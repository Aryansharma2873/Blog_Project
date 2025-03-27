from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import BlogPost,User,Comment
from django.core.mail import send_mail
from django.conf import settings
from blog.models import EmailVerificationToken  # Ensure this model exists


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")  # Remove confirm_password from user creation
        user = User.objects.create_user(**validated_data)
        user.is_verified = False  # ❌ Make user inactive until email verification
        user.save()

         # Generate JWT token for verification
        token = EmailVerificationToken.generate_token(user)

        # Store token in DB
        EmailVerificationToken.objects.create(user=user, token=token)

        # Send email with verification link
        verification_link = f"http://127.0.0.1:8000/api/verify-email/{token}/"
        send_mail(
            "Verify Your Email",
            f"Click the link to verify your email: {verification_link}",
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )

        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class BlogPostSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source="author.email", read_only=True)  # Add this line

    class Meta:
        model = BlogPost
        fields = ["id", "title", "description", "image", "created_at","author_email"]

    def get_image(self, obj):
        request = self.context.get("request")
        if obj.image:
            return request.build_absolute_uri(obj.image.url)
        return None

    def validate_title(self, value):
        """Ensure the title is at least 5 characters long"""
        if len(value) < 3:
            raise serializers.ValidationError("Title must be at least 5 characters long.")
        return value

    def validate_description(self, value):
        """Ensure the description is not empty"""
        if not value.strip():
            raise serializers.ValidationError("Description cannot be empty.")
        return value

    def validate_image(self, value):
        """Check image file size (max 2MB)"""
        if value and value.size > 5 * 1024 * 1024:  # 2MB limit
            raise serializers.ValidationError("Image size should not exceed 2MB.")
        return value
    
class CommentSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = ["id", "user", "content", "created_at"]