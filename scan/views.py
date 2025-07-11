import uuid

from asgiref.sync import async_to_sync, sync_to_async
from channels.layers import get_channel_layer
from drf_yasg.utils import swagger_auto_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from scan.serializers import ScanRequestSerializer

from .models import Scan


from urllib.parse import urlparse

class StartScanView(APIView):
    """
    Repository scan view
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=ScanRequestSerializer,
        responses={
            201: "Returns scan WebSocket URL",
            400: "Invalid request",
            422: "Invalid input data",
            500: "Internal server error",
        },
    )
    def post(self, request, *args, **kwargs):
        """
        Handle the POST request to start scanning a repository.
        The body should contain 'repo_url'.
        """
        # Validate and deserialize the input data
        serializer = ScanRequestSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {"status": "Invalid input", "message": serializer.errors}, status=400
            )

        repo_url = serializer.validated_data.get("repo_url")
        token = (
            "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"
        )

        try:
            # Create a new scan record in the database (this is synchronous, no need for sync_to_async)
            scan = Scan.objects.create(
                scan_id=str(uuid.uuid4()),  # Generate a unique scan ID
                repo_url=repo_url,
                status="in_progress",
            )

            # Retrieve the host (domain) from the request
            host = request.get_host()

            # Construct the WebSocket URL
            websocket_url = f"ws://{host}/ws/scan/{scan.scan_id}/"

            # Get the channel layer to send WebSocket messages
            channel_layer = get_channel_layer()

            # Trigger the scan and vulnerability detection from the WebSocket consumer
            async_to_sync(channel_layer.group_send)(
                f"scan_{scan.scan_id}",  # WebSocket group name
                {
                    "type": "start_scan",
                    "scan_id": scan.scan_id,
                    "repo_url": repo_url,
                    "token": token,
                },
            )

            return Response(
                {
                    "status": "Scan started",
                    "websocket_url": websocket_url,
                    "repo_url": repo_url,
                },
                status=201,
            )

        except Exception as e:
            return Response({"status": "Error", "message": str(e)}, status=500)
