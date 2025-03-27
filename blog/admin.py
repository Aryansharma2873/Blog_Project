from django.contrib import admin
from .models import User, BlogPost,Comment

admin.site.register(User)
admin.site.register(BlogPost)
admin.site.register(Comment)