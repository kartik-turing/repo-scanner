import json
import logging
from datetime import datetime

import requests
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings

logger = logging.getLogger(__name__)


class ScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """
        This method is called when a WebSocket connection is made.
        Once the connection is established, it will start the scan immediately.
        """
        # Retrieve scan_id from the URL route (path parameter)
        self.scan_id = self.scope["url_route"]["kwargs"]["scan_id"]
        self.room_group_name = f"scan_{self.scan_id}"

        # Log the connection attempt
        logger.debug(f"WebSocket connection attempt for scan {self.scan_id}")

        # Join the WebSocket group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

        # Accept the WebSocket connection
        await self.accept()

        # Notify client that the connection was established
        await self.send(
            text_data=json.dumps(
                {
                    "message": "Connection established",
                    "scan_id": self.scan_id,
                    "status": "pending",
                }
            )
        )

        logger.info(f"WebSocket connection accepted for scan {self.scan_id}")

        # Immediately start the scan once the connection is accepted
        await self.start_scan()

    async def disconnect(self, close_code):
        # Log the disconnection event
        logger.info(
            f"WebSocket disconnected for scan {self.scan_id} with close code {close_code}"
        )

        # Leave the WebSocket group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def start_scan(self):
        """
        This method is triggered to start the scanning process once the WebSocket connection is established.
        It begins the scanning process asynchronously.
        """
        from .models import Scan

        # Fetch the necessary data for scanning (scan_id, repo_url, token)
        scan = await sync_to_async(Scan.objects.get)(scan_id=self.scan_id)

        # Fetch repo_url and token from the database (or API request parameters)
        repo_url = scan.repo_url  # Assuming the repo_url is already set in the database
        token = (
            "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"  # Replace with your GitHub token
        )

        # Start scanning the repository
        await self.run_scan(scan_id=self.scan_id, repo_url=repo_url, token=token)

    async def run_scan(self, scan_id, repo_url, token):
        """
        This method initiates the scanning process, checks the repository, and detects vulnerabilities.
        """
        from .models import Scan

        try:
            # Fetch repository files (asynchronously)
            repo_files = await sync_to_async(self.get_repo_files)(repo_url, token)

            @sync_to_async
            def update_scan(scan_id, repo_url):
                return Scan.objects.filter(scan_id=scan_id).update(
                    repo_url=repo_url, status="in_progress"
                )

            await update_scan(self.scan_id, repo_url)
            # After scan is complete, send a completion message to the WebSocket group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "repo_files_fetched",
                    "scan_id": self.scan_id,
                    "status": "starting scan of files",
                },
            )

            # Scan repository files for vulnerabilities
            await self.scan_repo_files(repo_files)

            # After scan is completed, update scan status to 'completed'
            from .models import Scan

            scan = await sync_to_async(Scan.objects.get)(scan_id=scan_id)
            scan.status = "completed"
            await sync_to_async(scan.save)()

        except Exception as e:
            logger.error(f"Error during scan {scan_id}: {str(e)}")
            scan = await sync_to_async(Scan.objects.get)(scan_id=scan_id)
            scan.status = "failed"
            await sync_to_async(scan.save)()

    async def repo_files_fetched(self, event):
        await self.send(
            text_data=json.dumps(
                {"message": event["status"], "scan_id": event["scan_id"]}
            )
        )

    def get_repo_files(self, repo_url, token):
        """
        Fetch the repository files using GitHub API.
        """
        repo_owner, repo_name = repo_url.split("/")[-2], repo_url.split("/")[-1]
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents"
        headers = {"Authorization": f"token {token}"}

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise Exception("Failed to fetch repository contents")
        return response.json()

    async def scan_repo_files(self, repo_files):
        """
        Scan repository files for vulnerabilities (example: detecting MD5 hashes).
        """
        from .models import Vulnerability

        for file in repo_files:
            if file["type"] == "file":
                content = requests.get(file["download_url"]).text

                # Example: Check for MD5 hash function in the content
                if "md5" in content.lower():
                    vulnerability_payload = {
                        "scanId": self.scan_id,
                        "timestamp": datetime.now().isoformat() + "Z",
                        "filePath": file["path"],
                        "lineNumber": self.find_line_number(content, "md5"),
                        "severity": "HIGH",
                        "issueType": "Deprecated Encryption",
                        "issueCategory": "Cryptographic Weakness",
                        "issueDetail": {
                            "description": "Weak hash function MD5 detected",
                            "algorithm": "MD5",
                            "recommendedAlgorithm": "SHA-256 or SHA-3",
                            "codeSnippet": self.extract_code_snippet(content, "md5"),
                        },
                        "recommendation": "Upgrade to a stronger hashing function like SHA-256.",
                        "confidence": 0.98,
                    }

                    # Save the vulnerability to the database
                    await sync_to_async(Vulnerability.objects.create)(
                        scan_id=self.scan_id,
                        file_path=file["path"],
                        line_number=vulnerability_payload["lineNumber"],
                        severity=vulnerability_payload["severity"],
                        issue_type=vulnerability_payload["issueType"],
                        issue_category=vulnerability_payload["issueCategory"],
                        issue_detail=vulnerability_payload["issueDetail"],
                        recommendation=vulnerability_payload["recommendation"],
                        confidence=vulnerability_payload["confidence"],
                    )

                    # Send the vulnerability payload to the WebSocket group
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            "type": "vulnerability.detected",
                            "payload": vulnerability_payload,
                        },
                    )

    async def vulnerability_detected(self, event):
        """
        Handle the 'vulnerability.detected' message and send the vulnerability details to the WebSocket.
        """
        await self.send(text_data=json.dumps(event["payload"]))

    def find_line_number(self, content, keyword):
        """
        Find the line number where the keyword (e.g., 'md5') appears in the file content.
        """
        for i, line in enumerate(content.splitlines(), 1):
            if keyword in line:
                return i
        return 0

    def extract_code_snippet(self, content, keyword):
        """
        Extract a code snippet around the keyword (e.g., 'md5') in the file content.
        """
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if keyword in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return "\n".join(lines[start:end])
        return ""
