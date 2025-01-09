# Create a file called templatetags.py in your app directory
# Add the following code to templatetags.py

from django import template
from django.utils import timezone
from datetime import timedelta

register = template.Library()

@register.simple_tag
def calculate_expiration_date(trial_start):
    return trial_start + timedelta(minutes=3)  # Adjust the timedelta as needed
