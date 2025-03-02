import json
import uuid
from channels.generic.websocket import AsyncWebsocketConsumer
import requests
from django.conf import settings
from .models import Scan, Vulnerability
from asgiref.sync import sync_to_async
from datetime import datetime

class ScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.scan_id = str(uuid.uuid4())  # Generate a unique scan ID
        self.room_group_name = f'scan_{self.scan_id}'

        # Join the WebSocket group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # Create a new scan record in the database
        await sync_to_async(Scan.objects.create)(
            scan_id=self.scan_id,
            repo_url="",  # Will be updated in the receive method
            status='pending'
        )

    async def disconnect(self, close_code):
        # Leave the WebSocket group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        repo_url = data['repo_url']
        token = data['token']

        # Update the scan record with the repo URL
        scan = await sync_to_async(Scan.objects.get)(scan_id=self.scan_id)
        scan.repo_url = repo_url
        scan.status = 'in_progress'
        await sync_to_async(scan.save)()

        # Get the repository files (GitHub API)
        repo_files = await sync_to_async(self.get_repo_files)(repo_url, token)

        # Scan the files for vulnerabilities
        await self.scan_repo_files(repo_files)

        # Mark the scan as completed
        scan.status = 'completed'
        scan.completed_at = datetime.now()
        await sync_to_async(scan.save)()

    def get_repo_files(self, repo_url, token):
        # Fetch files from GitHub using the GitHub API
        repo_owner, repo_name = repo_url.split("/")[-2], repo_url.split("/")[-1]
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents"
        headers = {
            "Authorization": f"token {token}"
        }

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception("Failed to fetch repository contents")
        return response.json()

    async def scan_repo_files(self, repo_files):
        for file in repo_files:
            if file['type'] == 'file':
                content = requests.get(file['download_url']).text

                # Example: Check for MD5 hash function
                if 'md5' in content.lower():
                    vulnerability_payload = {
                        "scanId": self.scan_id,
                        "timestamp": datetime.now().isoformat() + "Z",
                        "filePath": file['path'],
                        "lineNumber": self.find_line_number(content, 'md5'),
                        "severity": "HIGH",
                        "issueType": "Deprecated Encryption",
                        "issueCategory": "Cryptographic Weakness",
                        "issueDetail": {
                            "description": "Weak hash function MD5 detected",
                            "algorithm": "MD5",
                            "recommendedAlgorithm": "SHA-256 or SHA-3",
                            "codeSnippet": self.extract_code_snippet(content, 'md5')
                        },
                        "recommendation": "Upgrade to a stronger hashing function like SHA-256.",
                        "confidence": 0.98
                    }

                    # Save the vulnerability to the database
                    await sync_to_async(Vulnerability.objects.create)(
                        scan_id=self.scan_id,
                        file_path=file['path'],
                        line_number=vulnerability_payload['lineNumber'],
                        severity=vulnerability_payload['severity'],
                        issue_type=vulnerability_payload['issueType'],
                        issue_category=vulnerability_payload['issueCategory'],
                        issue_detail=vulnerability_payload['issueDetail'],
                        recommendation=vulnerability_payload['recommendation'],
                        confidence=vulnerability_payload['confidence']
                    )

                    # Send the vulnerability payload to the WebSocket group
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            "type": "vulnerability.detected",
                            "payload": vulnerability_payload
                        }
                    )

    async def vulnerability_detected(self, event):
        # Send the vulnerability payload to the WebSocket
        await self.send(text_data=json.dumps(event['payload']))

    def find_line_number(self, content, keyword):
        # Find the line number where the keyword appears
        for i, line in enumerate(content.splitlines(), 1):
            if keyword in line:
                return i
        return 0

    def extract_code_snippet(self, content, keyword):
        # Extract a code snippet around the keyword
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if keyword in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return "\n".join(lines[start:end])
        return ""