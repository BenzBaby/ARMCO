# forms.py
from django import forms
from .models import Trackday

class TrackdayForm(forms.ModelForm):
    class Meta:
        model = Trackday
        fields = ['date']

# bikes/forms.py

from django import forms
from .models import Bike

class BikeForm(forms.ModelForm):
    class Meta:
        model = Bike
        fields = '__all__'
