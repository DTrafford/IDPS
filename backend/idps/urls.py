from django.conf.urls import include, url  # noqa
from django.contrib import admin
from django.views.generic import TemplateView
from django.urls import path

import django_js_reverse.views
from snifferapp.views import test_list


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    path("test/", test_list, name="test_list"),
    url(r'^jsreverse/$', django_js_reverse.views.urls_js, name='js_reverse'),

    url(r'^$', TemplateView.as_view(template_name='snifferapp/itworks.html'), name='home'),
]


