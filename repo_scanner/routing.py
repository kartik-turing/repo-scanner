from django.urls import re_path

from scan.consumers import ScanConsumer

websocket_urlpatterns = [
    re_path(r"ws/scan/(?P<scan_id>[a-f0-9-]+)/$", ScanConsumer.as_asgi()),
]
