from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from scan.serializers import ScanRequestSerializer
from django.http import JsonResponse
from rest_framework.permissions import AllowAny

from .consumers import ScanConsumer

consumer = ScanConsumer()

class StartScanView(APIView):
    """
    Repository scan view
    """

    permission_classes = [AllowAny]

    # Swagger schema with auto schema
    @swagger_auto_schema(
        request_body=ScanRequestSerializer,
        responses={
            201: "Returns scanned results",
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

        if serializer.is_valid():
            repo_url = serializer.validated_data.get('repo_url')
            token = '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'

            try:
                # Call your scanning logic here (same as in the consumer)
                repo_files = get_repo_files(repo_url, token)
                scan_results = scan_repo_files(repo_files)

                return JsonResponse({'status': 'Scan started', 'scan_results': scan_results})

            except Exception as e:
                return JsonResponse({'status': 'Error', 'message': str(e)}, status=400)

        return JsonResponse({'status': 'Invalid input', 'message': serializer.errors}, status=400)


# Helper Functions for Repo File Scanning
def get_repo_files(repo_url, token):
    return consumer.get_repo_files(repo_url, token)

def scan_repo_files(repo_files):
    return consumer.scan_repo_files(repo_files)
