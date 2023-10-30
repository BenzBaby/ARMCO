# forms.py
from django import forms
from .models import Trackday

class TrackdayForm(forms.ModelForm):
    class Meta:
        model = Trackday
        fields = ['date']
