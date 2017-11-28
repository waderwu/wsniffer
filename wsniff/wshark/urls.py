from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^packet/(?P<id>[0-9]+)$', views.packet_detail, name='packet'),
    url(r'^stream/(?P<stream_index>[0-9]+)$',views.stream, name='stream'),
]