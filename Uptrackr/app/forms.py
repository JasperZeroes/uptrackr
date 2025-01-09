from django import forms
from django_countries.widgets import CountrySelectWidget
from django_countries.fields import CountryField


class UserInputForm(forms.Form):
    email = forms.EmailField(label='Enter your email address')
    rss_url = forms.URLField(label='Enter your Upwork RSS URL')


class UserSignupForm(forms.Form):
    username = forms.CharField(label='Username', max_length=100)
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    email = forms.EmailField(label='Email')
    full_name = forms.CharField(label='Full Name', max_length=100, required=True)
    country = forms.CharField(widget=CountrySelectWidget(attrs={'class': 'form-control'}))

class UserLoginForm(forms.Form):
    username = forms.CharField(label='Username', max_length=100, required=True)
    password = forms.CharField(label='Password', widget=forms.PasswordInput)


class UpdateAccountForm(forms.Form):
    username = forms.CharField(label='New Username', max_length=100, required=False)
    password = forms.CharField(label='New Password', widget=forms.PasswordInput, required=False)
    email = forms.EmailField(label='New Email', required=False)
    full_name = forms.CharField(label='New Full Name', max_length=100, required=False)
    country = forms.CharField(label='New Country', max_length=50, required=False)


class ResetAccountForm(forms.Form):
    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput)
    confirm_password = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New Password and Confirm Password do not match.")

