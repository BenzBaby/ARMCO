from django.contrib import admin
from .models import CustomUser
admin.site.register(CustomUser)

from django.contrib import admin
from .models import TrackdayRegistration

admin.site.register(TrackdayRegistration)



from django.contrib import admin
from .models import CompanyTrackdayRegistration

class CompanyTrackdayRegistrationAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_name', 'trackday_date')
    list_filter = ('trackday_date',)
    search_fields = ('company_name',)
    list_per_page = 20

admin.site.register(CompanyTrackdayRegistration, CompanyTrackdayRegistrationAdmin)

# from django.contrib import admin
# from .models import UserProfile

# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'role', 'lap_time')
#     list_filter = ('role', 'lap_time')
#     search_fields = ('user__username', 'user__email', 'role', 'lap_time')

