import aiohttp
import asyncio
import json
import logging
from datetime import datetime
import os
import pygit2


import requests
from asgiref.sync import sync_to_async

from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings

from .scanner import RepoScanner

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
        self.scanner = RepoScanner(self.scan_id)

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
    
        # Start scanning the repository
        await self.run_scan(scan_id=self.scan_id, repo_url=repo_url)

    async def run_scan(self, scan_id, repo_url):
        """
        This method initiates the scanning process, checks the repository, and detects vulnerabilities.
        """
        from .models import Scan

        try:
            repo_name = repo_url.strip('/').split('/')[-1]
            self.local_path = os.path.join(os.getcwd(), "repositories", repo_name)
            # Fetch repository files (asynchronously)
            if not os.path.exists(self.local_path):
                logger.info("Cloning repository ...")
                await self.get_repo_files(repo_url)
                
            logger.info("Repository cloned successfully.")

            @sync_to_async
            def update_scan(scan_id, repo_url, status):
                return Scan.objects.filter(scan_id=scan_id).update(
                    repo_url=repo_url, status=status
                )

            await update_scan(self.scan_id, repo_url, status="fetching files")

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
            logger.info("Scanning repository files...")
            await self.scanner.scan_repo_files(repo_dir=self.local_path, scan_id=scan_id)
            logger.info("Repository files scanned successfully.")

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

    async def scan_complete(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "message": "Scan complete",
                    "scan_id": event["scan_id"],
                    "status": event["status"],
                    "vulnerabilities_found": event["vulnerabilities_found"],
                }
            )
        )

    async def vulnerability_detected(self, event):
        await self.send(text_data=json.dumps(event["vulnerability"]))


    async def get_repo_files(self, repo_url):
        """
        Clone the repository from GitHub to the local machine.
        """
        try:
            if repo_url.startswith("https://"):
                repo_url = repo_url.replace("https://github.com/", "git@github.com:")
            repo_url = f"{repo_url}.git"
            os.makedirs(os.path.dirname(self.local_path), exist_ok=True)
    
            # Clone the repository to the local path
            logger.info(f"Cloning the repository from {repo_url}...")
            callbacks = pygit2.RemoteCallbacks(
                credentials=self.get_ssh_credentials()
            )
            pygit2.clone_repository(repo_url, self.local_path, callbacks=callbacks)
            logger.info(f"Repository cloned successfully to {self.local_path}")
        except Exception as e:
            logger.error(f"Failed to clone the repository: {str(e)}")
            raise e
        
    def get_ssh_credentials(self):
        """
        Create SSH credentials for pygit2 using a private key.
        """
        return pygit2.Keypair(
            username="git", 
            pubkey=os.path.expanduser("~/.ssh/id_rsa.pub"),
            privkey= os.path.expanduser("~/.ssh/id_rsa"),
            passphrase="pass"
        )