from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

class ActivationBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = User.objects.get(username=username)
            if user.is_active:
                if user.check_password(password):
                    return user
            return None
        except User.DoesNotExist:
            return None
