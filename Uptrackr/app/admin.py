
from django.contrib import admin
from .models import CustomUser,CustomUserManager
from .models import FreeTrialUser 
admin.site.register(FreeTrialUser)
from .models import SubscriptionPayment

admin.site.register(CustomUser)

@admin.register(SubscriptionPayment)
class SubscriptionPaymentAdmin(admin.ModelAdmin):
    list_display = ['user_name', 'event_name', 'created_at', 'total_formatted', 'status', 'expiration_date']
    search_fields = ['user_name', 'event_name']
    list_filter = ['event_name', 'status']

