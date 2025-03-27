from django.contrib.auth import authenticate, login, logout,get_user_model
from django.shortcuts import redirect
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework import status,generics, permissions
from rest_framework.views import APIView
from .serializers import RegisterSerializer, UserSerializer,BlogPostSerializer,LoginSerializer,CommentSerializer
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from blog.models import User,BlogPost, EmailVerificationToken,Comment
from django.conf import settings
from django.utils.http import urlencode
import jwt
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import logging

logger = logging.getLogger(__name__)
User = get_user_model()
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['GET'])
def verify_email(request, token):
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        user = User.objects.get(id=user_id)

        # Check if token exists in DB
        stored_token_obj = EmailVerificationToken.objects.filter(user=user).first()
        if not stored_token_obj or stored_token_obj.token != token: 
            return Response({'error': 'Invalid or expired token.'}, status=400)

        # Activate user
        user.is_verified = True
        user.save()

        # Delete the verification token after use
        EmailVerificationToken.objects.filter(user=user).delete()

        # Redirect to login page with success message
        params = urlencode({'message': 'Email Verified Successfully! 🎉'})

        return redirect(f'http://localhost:5173/login?{params}')  # Redirect to frontend login page
    
    except jwt.ExpiredSignatureError:
        return Response({'error': 'Verification token expired. Please register again.'}, status=400)
    except jwt.DecodeError:
        return Response({'error': 'Invalid token.'}, status=400)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=400)
    
@api_view(['POST'])
def forgot_password_request(request):
    """Sends password reset link via email."""
    email = request.data.get("email")
    user = User.objects.filter(email=email).first()

    if not user:
        return Response({"error": "No account found with this email."}, status=400)

    # Generate token
    token = default_token_generator.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

    # Create password reset URL
    reset_url = f"http://localhost:5173/reset-password/{uidb64}/{token}/"

    # Send email
    send_mail(
        "Password Reset Request",
        f"Click the link below to reset your password:\n{reset_url}",
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

    return Response({"message": "Password reset link sent! Check your email."}, status=200)


@api_view(['POST'])
def reset_password(request, uidb64, token):
    """Verifies token and allows user to reset password."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        return Response({"error": "Invalid reset link."}, status=400)

    if not default_token_generator.check_token(user, token):
        return Response({"error": "Token expired or invalid."}, status=400)

    new_password = request.data.get("password")
    confirm_password = request.data.get("confirm_password")

    if new_password != confirm_password:
        return Response({"error": "Passwords do not match."}, status=400)

    user.set_password(new_password)
    user.save()
    return Response({"message": "Password reset successful!"}, status=200)
    
class UserListView(generics.ListAPIView):
    queryset = User.objects.all()  # Fetch all users
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]
    
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            logger.error(f"Invalid login data: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # 🔹 Check if user exists
        try:
            user = User.objects.get(email=email)
            logger.info(f"User found: {user.email}")
        except User.DoesNotExist:
            logger.error("User not found!")
            return Response({"error": "User not found. Please Register!!"}, status=status.HTTP_400_BAD_REQUEST)

        # 🔹 Ensure user is verified before authentication
        if not user.is_verified:
            logger.warning(f"User {user.email} is not verified.")
            return Response({"error": "Please verify your email first, then try logging in."}, status=status.HTTP_403_FORBIDDEN)

        print(f"Debug: Email = {email}, Password = {password}")  # 🔹 Debug line
        
        user = authenticate(request, username=email, password=password)  # 🔹 Authenticate user

        print(f"Debug: Authenticated User = {user}")  # 🔹 Check if user is None

        if user is None:
            logger.error(f"Authentication failed for user {email}")
            return Response({"error": "Invalid email or password."}, status=status.HTTP_400_BAD_REQUEST)

        # 🔹 Generate JWT tokens
        tokens = get_tokens_for_user(user)
        logger.info(f"User {user.email} logged in successfully.")

        return Response({
            "access": tokens['access'],
            "refresh": tokens['refresh'],
            "message": "Login successful!"
        }, status=status.HTTP_200_OK)


class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out"}, status=200)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=400)
        
class BlogCreateView(generics.CreateAPIView):
    queryset = BlogPost.objects.all().order_by('-created_at')
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.IsAuthenticated]  # Only logged-in users can create posts

    def post(self, request):
        serializer = BlogPostSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            serializer.save(author=request.user)  # ✅ Assign blog to the logged-in user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class BlogPagination(PageNumberPagination):
    page_size = 8  # Number of blogs per page
    page_size_query_param = 'page_size'
    max_page_size = 10
    
# List All Blog Posts (No Authentication Required)
class BlogListView(generics.ListAPIView):
    queryset = BlogPost.objects.all().order_by("-created_at")  # Show newest posts first
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.AllowAny]
    pagination_class = BlogPagination
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ['title', 'description']  # Search by title & description

# Retrieve, Update, and Delete a Single Blog Post
class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]  # Read for all, edit for author only

    def perform_update(self, serializer):
        if self.request.user == self.get_object().author:
            serializer.save()
        else:
            raise PermissionError("You can only edit your own blog posts!")

    def perform_destroy(self, instance):
        if self.request.user == instance.author:
            instance.delete()
        else:
            raise PermissionError("You can only delete your own blog posts!")
        
class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
class CommentListCreateView(generics.ListCreateAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        blog_id = self.kwargs["blog_id"]
        return Comment.objects.filter(blog_id=blog_id).order_by("-created_at")

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, blog_id=self.kwargs["blog_id"])
    
class CommentDeleteView(generics.RetrieveDestroyAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    lookup_field = "id"  # Add this line

    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        comment = self.get_object()
        if comment.user != request.user:
            return Response({"error": "You can only delete your own comments."}, status=403)
        return super().delete(request, *args, **kwargs)