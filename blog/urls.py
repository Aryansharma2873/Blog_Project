from django.urls import path
from .views import RegisterView, LogoutView, UserListView,BlogCreateView,BlogListView,BlogDetailView,LoginView,UserProfileView,CommentListCreateView,CommentDeleteView,verify_email,forgot_password_request, reset_password
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/<str:token>/', verify_email, name='verify-email'),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),  # Login
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),  # Refresh Token
    path('login/',LoginView.as_view() , name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('users/', UserListView.as_view(), name='user-list'),
    path("blogs/", BlogListView.as_view(), name="create_blog"),
    path("blogs/create/", BlogCreateView.as_view(), name="create_blog"),  # Create new blog
    path("blogs/<int:pk>/", BlogDetailView.as_view(), name="blog_detail"),  # View/Update/Delete a blog
    path("forgot-password/", forgot_password_request, name="forgot_password_request"),
    path("reset-password/<str:uidb64>/<str:token>/", reset_password, name="reset_password"),
    path("user/profile/", UserProfileView.as_view(), name="user_profile"),
    path('blogs/<int:blog_id>/comments/', CommentListCreateView.as_view(), name='blog-comments'),
    path("blogs/<int:blog_id>/comments/<int:id>/", CommentDeleteView.as_view(), name="delete-comment"),
]

