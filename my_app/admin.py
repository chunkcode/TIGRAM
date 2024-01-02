from django.contrib import admin
from .models import District,Taluka,Village,TreeSpecies,RolePermission


admin.site.register(District)
admin.site.register(Taluka)
admin.site.register(Village)
admin.site.register(TreeSpecies)
admin.site.register(RolePermission)