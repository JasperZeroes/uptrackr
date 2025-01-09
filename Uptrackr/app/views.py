from rest_framework.decorators import api_view, permission_classes
from django_countries import countries
import time
from django.utils.encoding import force_str
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest
from django.contrib import messages
from .models import FreeTrialUser,SubscriptionPayment
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from .models import CustomUser
from django.urls import reverse
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from main.reset_password import send_reset_password_mail
from django.contrib.auth.models import User
from main.send_activation_mail import send_activation_mail
from django.shortcuts import render, redirect
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from .serializers import CustomUserSerializer
from rest_framework import generics
from .models import CustomUser
from .forms import UserInputForm, UserLoginForm, UserSignupForm
from .forms import UpdateAccountForm, ResetAccountForm
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from datetime import datetime, timedelta
from django.utils import timezone
from threading import Thread, Event
from main.main import job
from django.http import HttpResponseForbidden
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from dotenv import load_dotenv
import os
import hashlib
import hmac

load_dotenv()



terminate_signal = Event()

from main.main import fetch_xml_data, parse_xml
@login_required
def dashboard(request):
    if request.method == 'POST':
        rss_url = request.POST.get('rss_url')
        xml_data = fetch_xml_data(rss_url)
        if xml_data:
            jobs = parse_xml(xml_data)
            context = {'jobs': jobs}
            return render(request, 'dashboard.html', context)
        else:
            error_message = "Failed to fetch job data."
            return render(request, 'dashboard.html', {'error_message': error_message})
    else:
        # Handle GET requests where users access the dashboard page
        return render(request, 'dashboard.html')

# Form for alert
@login_required
def input_form(request):
    if request.method == 'POST':
        form = UserInputForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            rss_url = form.cleaned_data['rss_url']
            user = request.user
            script_thread = Thread(target=run_job, args=(email, rss_url))
            script_thread.start()
            # Check if the user already has a subscription
            subscribed_user = SubscriptionPayment.objects.filter(user_name=user).first()
            if subscribed_user:
                return redirect('main_sub')
            else:
                # Create FreeTrialUser object if the user doesn't have a subscription
                FreeTrialUser.objects.create(user=user)
                return redirect('success')
    else:
        return HttpResponseForbidden("Access Denied: Access to this page is not allowed.")
    return render(request, 'alert.html', {'form': form})
# To run script
def run_job(email, rss_url):
    global terminate_signal
    while not terminate_signal.is_set():
        job(email, rss_url)
        time.sleep(0)  
# pricing
# def pricing_page(request):
#     global terminate_signal
#     user = request.user
#     month_sub_on = False
#     year_sub_on = False
#     sub_message = None
#     year_sub_message = None
#     print("Got up to this point")
#     trial_user = FreeTrialUser.objects.filter(user=user).first()
#     if trial_user:
#         if trial_user.start_date + timedelta(minutes=10080) <= timezone.now():
#             trial_message = 'Your free trial has expired. Please subscribe to continue.'
#             terminate_signal.set()
#         else:
#             trial_message = 'Your free trial is already active. Please go back to <a href="dashboard">dashboard</a> to see your stats.'
#     else:
#         trial_message = None
        
#     # Check if the user already has a subscription
#     subscribed_user = SubscriptionPayment.objects.filter(user_name=user).first()
#     if subscribed_user:
#         if subscribed_user.total_formatted == '$5.00':
#             if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():

#                 sub_message = 'Your monthly subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
#                 terminate_signal.set() 
#             else:
#                 month_sub_on = True
#                 terminate_signal.clear()
#         elif subscribed_user.total_formatted == '$48.00':
#             if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():

#                 year_sub_message = 'Your annual subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
#                 terminate_signal.set()
#             else:
#                 year_sub_on = True
#                 terminate_signal.clear()
#     else:
#         pass

#     if request.method == 'POST':
#         if 'plan' in request.POST:
#             plan = request.POST['plan']
#             if plan == 'free':
    
#                 return redirect('alert')  
#             elif plan == 'monthly':
#                 user_name = request.user.username
#                 variant_id ='73532fcc-0a52-46c2-824c-86e7baca997e'
#                 checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
#                 return redirect(checkout_url)                
#             elif plan == 'annual':
#                 user_name = request.user.username
#                 variant_id = '43d4f9bf-ae1e-47e6-a66e-5c4eeac8a20d'  # Adjust this to your actual variant ID
#                 checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
#                 return redirect(checkout_url)   
#     return render(request, 'pricing.html', {'trial_message': trial_message,'month_sub_on': month_sub_on,'year_sub_on':year_sub_on, 'sub_message': sub_message,'year_sub_message':year_sub_message})


# def pricing_page(request):
#     global terminate_signal
#     user = request.user
#     month_sub_on = False
#     year_sub_on = False
#     sub_message = None
#     year_sub_message = None
#     trial_message = None

#     # Only perform user-specific checks if the user is authenticated
#     if user.is_authenticated:
#         trial_user = FreeTrialUser.objects.filter(user=user).first()
#         if trial_user:
#             if trial_user.start_date + timedelta(minutes=10080) <= timezone.now():
#                 trial_message = 'Your free trial has expired. Please subscribe to continue.'
#                 terminate_signal.set()
#             else:
#                 trial_message = 'Your free trial is already active. Please go back to <a href="dashboard">dashboard</a> to see your stats.'
        
#         # Check if the user already has a subscription
#         subscribed_user = SubscriptionPayment.objects.filter(user_name=user).first()
#         if subscribed_user:
#             if subscribed_user.total_formatted == '$5.00':
#                 if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():
#                     sub_message = 'Your monthly subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
#                     terminate_signal.set()
#                 else:
#                     month_sub_on = True
#                     terminate_signal.clear()
#             elif subscribed_user.total_formatted == '$48.00':
#                 if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():
#                     year_sub_message = 'Your annual subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
#                     terminate_signal.set()
#                 else:
#                     year_sub_on = True
#                     terminate_signal.clear()

#     # Handle POST request for subscription plans
#     if request.method == 'POST':
#         if user.is_authenticated and 'plan' in request.POST:
#             plan = request.POST['plan']
#             if plan == 'free':
#                 return redirect('alert')
#             elif plan == 'monthly':
#                 user_name = request.user.username
#                 variant_id = '73532fcc-0a52-46c2-824c-86e7baca997e'
#                 checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
#                 return redirect(checkout_url)
#             elif plan == 'annual':
#                 user_name = request.user.username
#                 variant_id = '43d4f9bf-ae1e-47e6-a66e-5c4eeac8a20d'
#                 checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
#                 return redirect(checkout_url)

#     return render(request, 'pricing.html', {
#         'trial_message': trial_message,
#         'month_sub_on': month_sub_on,
#         'year_sub_on': year_sub_on,
#         'sub_message': sub_message,
#         'year_sub_message': year_sub_message
#     })

# from django.shortcuts import render, redirect
# from django.utils.timezone import now
# from datetime import timedelta
# from app.models import FreeTrialUser, SubscriptionPayment  # Adjust import to your app's actual name
# from django.contrib.auth.decorators import login_required

def pricing_page(request):
    global terminate_signal
    user = request.user
    month_sub_on = False
    year_sub_on = False
    sub_message = None
    year_sub_message = None
    trial_message = None

    # Only perform user-specific checks if the user is authenticated
    if user.is_authenticated:
        trial_user = FreeTrialUser.objects.filter(user=user).first()
        if trial_user:
            if trial_user.start_date + timedelta(minutes=6000) <= timezone.now():
                trial_message = 'Your free trial has expired. Please subscribe to continue.'
                terminate_signal.set()
            else:
                trial_message = 'Your free trial is already active. Please go back to <a href="dashboard">dashboard</a> to see your stats.'
        
        # Check if the user already has a subscription
        subscribed_user = SubscriptionPayment.objects.filter(user_name=user).first()
        if subscribed_user:
            if subscribed_user.total_formatted == '$5.00':
                if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():
                    sub_message = 'Your monthly subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
                    terminate_signal.set()
                else:
                    month_sub_on = True
                    terminate_signal.clear()
            elif subscribed_user.total_formatted == '$48.00':
                if subscribed_user.created_at + timedelta(minutes=10080) <= timezone.now():
                    year_sub_message = 'Your annual subscription has expired. Please wait for your subscription to autorenew to continue or click the button below to re-subscribe.'
                    terminate_signal.set()
                else:
                    year_sub_on = True
                    terminate_signal.clear()

    # Handle POST request for subscription plans
    if request.method == 'POST':
        if 'plan' in request.POST:
            plan = request.POST['plan']
            if plan == 'free':
                if not user.is_authenticated:
                    # Redirect to login with `next` parameter set to the current path
                    return redirect(f'{reverse("login")}?next={request.path}')
                return redirect('alert')  # Authenticated users proceed to the alert page
            elif plan == 'monthly':
                if not user.is_authenticated:
                    return redirect('login')  # Redirect to login if user is not authenticated
                user_name = request.user.username
                variant_id = '73532fcc-0a52-46c2-824c-86e7baca997e'
                checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
                return redirect(checkout_url)
            elif plan == 'annual':
                if not user.is_authenticated:
                    return redirect('login')  # Redirect to login if user is not authenticated
                user_name = request.user.username
                variant_id = '43d4f9bf-ae1e-47e6-a66e-5c4eeac8a20d'
                checkout_url = f'https://uptrackr.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][user_name]={user_name}'
                return redirect(checkout_url)

    return render(request, 'pricing.html', {
        'trial_message': trial_message,
        'month_sub_on': month_sub_on,
        'year_sub_on': year_sub_on,
        'sub_message': sub_message,
        'year_sub_message': year_sub_message
    })







SECRET_KEY =  os.environ.get("SECRETE")
print('SCRETE KEY IS', SECRET_KEY)

# Webhook to get data from lemon squeezy
@csrf_exempt
def webhook_callback(request):
    if request.method == 'POST':
        # Get the signature from the request headers
        signature = request.headers.get('X-Signature')

        # Calculate the digest using HMAC-SHA256
        digest = hmac.new(SECRET_KEY.encode(), request.body, hashlib.sha256).hexdigest()
        
        # Compare the calculated digest with the received signature
        if hmac.compare_digest(digest, signature):
            # If the signatures match, process the webhook payload
            try:
                # Parse the JSON payload
                payload = json.loads(request.body)
                event_name = payload['meta']['event_name']
                if event_name == 'subscription_payment_success':
                    custom_data = payload['meta']['custom_data']
                    user_name = custom_data['user_name']
                    created_at = datetime.strptime(payload['data']['attributes']['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ')
                    total_formatted = payload['data']['attributes']['total_formatted']
                    status = payload['data']['attributes']['status']
                    # Calculate expiration date based on total amount
                    if total_formatted == '$5.00':
                        expiration_date = created_at + timedelta(minutes=10080)
                    elif total_formatted == '$48.00':
                        expiration_date = created_at + timedelta(minutes=10080)
                    else:
                        expiration_date = None  # Or handle other cases as needed

                    # Save data to database
                    subscription_payment, created = SubscriptionPayment.objects.get_or_create(
                        user_name=user_name,
                        defaults={
                            'event_name': event_name,
                            'created_at': created_at,
                            'total_formatted': total_formatted,
                            'status': status,
                            'expiration_date': expiration_date
                        }
                            )

                            # If the object already existed, update its fields with the new data
                    if not created:
                        subscription_payment.event_name = event_name
                        subscription_payment.created_at = created_at
                        subscription_payment.total_formatted = total_formatted
                        subscription_payment.status = status
                        subscription_payment.expiration_date = expiration_date
                        subscription_payment.save()
                        
                    print('Data Saved')

                # Construct the JSON response
                response_data = {
                    'status': 'success',
                    'message': 'Webhook processed successfully',
                    'payload': payload  # Include the payload in the response if needed
                }
                
                # Return the JSON response
                return JsonResponse(response_data, status=200)
            except json.JSONDecodeError:
                # If the payload is not valid JSON, respond with a bad request status code
                return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
        else:
            # If the signatures don't match, respond with an unauthorized status code
            return JsonResponse({'error': 'Invalid signature'}, status=401)
    else:
        # If the request method is not POST, respond with a method not allowed status code
        return JsonResponse({'error': 'Method not allowed'}, status=405)



def sign_up(request):
    countries_list = countries
    if request.method == 'POST':
        form = UserSignupForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            full_name = form.cleaned_data['full_name']
            password = form.cleaned_data['password']
            
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                error_message = "Email address is already in use. Please use a different email address."
                return render(request, 'signup.html', {'message': error_message, 'form': form, 'countries': countries_list})

            try:
                user = User.objects.create_user(username=username, email=email, password=password, is_active=False)
                user.first_name = full_name
                user.save()
            except IntegrityError:
                error_message = "Username already exists. Please choose a different username."
                return render(request, 'signup.html', {'message': error_message})            
            # Generate token for email verification
            username = user.username
            token = default_token_generator.make_token(user) 
            current_domain = HttpRequest.get_host(request)
            activation_link = f'{request.scheme}://{current_domain}{reverse("activate", kwargs={"uidb64": urlsafe_base64_encode(force_bytes(user.pk)), "token": token})}'
            send_activation_mail(email, username, activation_link)
            # Redirect to a page indicating successful signup
            return render(request, 'signup_success.html')
    else:
        form = UserSignupForm()
    return render(request, 'signup.html', {'countries': countries_list, 'form': form})

def resend_activation_mail(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Handle the case where the user with the provided email doesn't exist
            error_message = 'User with this email address does not exist.'
            return render(request, 'resend_activation_mail.html', {'error_message': error_message})
        except MultipleObjectsReturned:
            error_message = 'Multiple users found with this email address. Please contact support.'
            return render(request, 'resend_activation_mail.html', {'error_message': error_message})
        # Generate token for email verification
        username = user.username
        token = default_token_generator.make_token(user)
        current_domain = request.get_host()
        activation_link = f'{request.scheme}://{current_domain}{reverse("activate", kwargs={"uidb64": urlsafe_base64_encode(force_bytes(user.pk)), "token": token})}'
        # Send activation email
        send_activation_mail(email, username,activation_link)
        # Display success message
        message = """Activation email has been sent successfully
                        """
        return render(request, 'resend_activation_mail.html',{'message':message})
    else:
        return render(request, 'resend_activation_mail.html')

       
def activate_account(request, uidb64, token):
    form = UserLoginForm()
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        # Activate user account
        user.is_active = True
        user.save()
        return render(request, 'activation_successful.html')
    else:
        return render(request, 'login.html', {'message': "Unable to actiavte your account <a href='/resend_activation'>Click here to resend activation link</a>", 'form': form})

class UserListAPIView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

# This login endpoint is used to test if the dashboard will be... 
# ... shown to users upon successful login 
def log_in(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        try:
            user = User.objects.get(username=username)
            # Check password validity here and handle login accordingly
        except ObjectDoesNotExist:
            error_message = "User does not exist. Please register or check your credentials."
            return render(request, 'login.html', {'message': error_message})
        user = authenticate(request, username=username, password=password)
        user_check  =  User.objects.get(username=username)
        if user is not None:
            if user.is_active:
                login(request, user)
                # Redirect to the home page
                return redirect('home')
        elif user is None and not user_check.is_active:
                # Account is not activated
                message = "Account not activated. <a href='/resend_activation'>Click here to resend activation link</a>"
                return render(request, 'login.html', {'message': message})
        elif user is None and user_check.is_active:
            # Invalid login credentials
            message = """Invalid login credentials. \n
                        """
            return render(request, 'login.html', {'message': message})
        elif user is None and user_check is None:
            comment = get_object_or_404(username=username)
            messages.error(request, 'User does not exist.')
          
    else:
        form = UserLoginForm()
    return render(request, 'login.html', {'form': form})


def log_out(request):
    logout(request)
    return redirect('login')


@login_required
def update_account(request):
    if request.method == 'POST':
        form = UpdateAccountForm(request.POST)

        if form.is_valid():
            # Update user information
            request.user.username = form.cleaned_data.get('username', request.user.username)
            request.user.email = form.cleaned_data.get('email', request.user.email)
            request.user.full_name = form.cleaned_data.get('full_name')
            request.user.country = form.cleaned_data.get('country')

            # Update password only if it's provided in the form
            new_password = form.cleaned_data.get('password')
            if new_password:
                request.user.set_password(new_password)

            request.user.save()

            # Update the session with the new user details
            update_session_auth_hash(request, request.user)

            messages.success(request, 'Your account has been updated successfully!')
            logout(request)  # Logout the user after updating
            return redirect('login')  # Redirect to the login page after update
    else:
        form = UpdateAccountForm()

    return render(request, 'update_account.html', {'form': form})

def password_reset_request(request):

    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Handle the case where the user with the provided email doesn't exist
            return render(request, 'reset_password.html', {'error_message': 'User with this email address does not exist.'})
        except MultipleObjectsReturned:
            error_message = 'Multiple users found with this email address. Please contact support.'
            return render(request, 'resend_activation_mail.html', {'error_message': error_message})
        
        # Generate password reset token
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))  # Encode the user's primary key
        reset_url = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))
        username = user.username
        # Send password reset email
        send_reset_password_mail(email, username, reset_url)
        # Redirect to a page indicating that the password reset email has been sent
        return render(request, 'reset_password.html',{'message':'We have sent a reset link to your email. Please click on the link to reset your password.'})
    else:
        return render(request, 'reset_password.html')



def password_reset_confirm(request, uidb64, token):
    
    print("UIDb64:", uidb64)  # Add this line to log uidb64 value
    
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        user = None
    except Exception as e:
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password')
            user.set_password(password)
            user.save()
            message = 'Your password has been successfully reset. You can now login with your new password'
            return render(request, 'password_reset_confirm.html', {'message': message})
        else:
            # If request method is not POST, render the form without the message
            return render(request, 'password_reset_confirm.html')
    else:
        # Handle invalid or expired token
        messages.error(request, 'Invalid or expired password reset link.')
        return redirect('password_reset')    
    



#-----------------------------Rendering 1 page  ----------------------------------------------------------------------#
@login_required
def base_view(request):
    return render(request, 'base.html')

def base_2_view(request):
    return render(request, 'base_html_2.html')

def main_sub(request):
    return render(request, 'main_sub.html')

def reset_password(request):
    return render(request, 'reset_password.html')

def home_page(request):
    return render(request, 'index.html')

def success_page(request):
    return render(request, 'success.html')



def sigup_sucess_page(request):
    return render(request, 'signup_success.html')

def skrill_form(request):
    return render(request, 'skrill.html')












