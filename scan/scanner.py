import ast
import asyncio
import json
import os
import re
import shutil
import subprocess
from datetime import datetime

import aiofiles  # For asynchronous file I/O
import esprima
import javalang
import phply
from channels.layers import get_channel_layer

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .utils import calculate_entropy, detect_high_entropy_strings

import logging

logger = logging.getLogger(__name__)


class RepoScanner:
    def __init__(self, scan_id, config_path=os.path.join(os.getcwd(), "config.json")):
        self.checks = self.load_config(config_path)
        self.room_group_name = f"scan_{scan_id}"

    def load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            return config.get("checks", [])
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return []

    async def scan_repo_files(self, repo_dir, scan_id):
        """
        Recursively scan files in the local repository directory.
        """
        self.scan_id = scan_id
        vulnerabilities = []

        # Walk through the repo directory and process each file
        await self._scan_files(repo_dir, vulnerabilities)

        # Check for library dependencies and SSL/TLS vulnerabilities
        vulnerabilities.extend(await self.library_dependency_checks())
        vulnerabilities.extend(await self.ssl_tls_checks())

        # Send a status message to the WebSocket client
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "scan_complete",
                "scan_id": self.scan_id,
                "status": "complete",
                "vulnerabilities_found": len(vulnerabilities),
            },
        )

        return vulnerabilities

    async def _scan_files(self, repo_dir, vulnerabilities):
        """
        Recursively iterate through the local repository directory.
        Process each file asynchronously.
        """
        for dirpath, dirnames, filenames in os.walk(repo_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)

                # Only process text-based files (skip binary files)
                if await self._is_text_file(file_path):
                    logger.info(f"Processing file: {file_path}")
                    # Read the file asynchronously
                    content = await self._read_file(file_path)

                    if content:
                        # Process the file content
                        await self.process_file(file_path, content, vulnerabilities)

    async def _is_text_file(self, file_path):
        """
        Check if a file is a text-based file (ignores binary files).
        """
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8', errors='ignore') as f:
                await f.read()  # Try reading the file
            return True
        except:
            return False

    async def _read_file(self, file_path):
        """
        Asynchronously read the file content.
        """
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8', errors='ignore') as f:
                return await f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None

    async def process_file(self, file_path, content, vulnerabilities):
        """
        Process the file content and detect vulnerabilities.
        """
        try:
            file_content_lower = content.lower()

            # Regex-based checks
            vulnerabilities.extend(await self.regex_checks(content, file_path, file_content_lower))

            # AST Parsing
            if file_path.endswith(".py"):
                vulnerabilities.extend(await self.ast_analysis_python(content, file_path))
            elif file_path.endswith(".java"):
                vulnerabilities.extend(await self.ast_analysis_java(content, file_path))
            elif file_path.endswith((".js", ".ts")):
                vulnerabilities.extend(await self.ast_analysis_javascript(content, file_path))
            elif file_path.endswith(".php"):
                vulnerabilities.extend(await self.ast_analysis_php(content, file_path))

            # Check for hardcoded secrets
            vulnerabilities.extend(await self.entropy_analysis(content, file_path))

            # Certificate Validation (if file is a certificate)
            if file_path.endswith((".crt", ".pem")):
                vulnerabilities.extend(await self.certificate_validation(content, file_path))
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

    async def create_vulnerability_payload(self, content, file_path, category, issue, severity, description, code_snippet=None, line_number=None, recommended_algorithm=None):
        try:
            # Format the vulnerability data to match the required structure
            vulnerability_payload = {
                "scanId": self.scan_id,
                "timestamp": datetime.now().isoformat() + "Z",
                "filePath": file_path,
                "lineNumber": line_number if line_number else self.find_line_number(content, description),
                "severity": severity,
                "issueType": category,
                "issueCategory": "Cryptographic Weakness",
                "issueDetail": {
                    "description": description,
                    "algorithm": issue,
                    "recommendedAlgorithm": recommended_algorithm,
                    "codeSnippet": code_snippet or self.extract_code_snippet(content, description),
                },
                "recommendation": "Upgrade to a stronger hashing function like SHA-256." if category == "Cryptographic Weakness" else "Review the configuration.",
                "confidence": 0.98,
            }

            # Send the vulnerability payload to the WebSocket group
            self.channel_layer = get_channel_layer()
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "vulnerability_detected",
                    "scan_id": self.scan_id,
                    "status": "vulnerability_payload",
                    "vulnerability": vulnerability_payload,
                },
            )
        except Exception as e:
            logger.error(f"Error creating vulnerability payload: {e}")

    def find_line_number(self, content, keyword):
        """
        Find the line number where the keyword (e.g., 'md5') appears in the file content.
        """
        try:
            for i, line in enumerate(content.splitlines(), 1):
                if keyword in line:
                    return i
            return 0
        except Exception as e:
            logger.error(f"Error finding line number: {e}")
            return 0
    
    def extract_code_snippet(self, content, keyword):
        """
        Extract a code snippet around the keyword (e.g., 'md5') in the file content.
        """
        try:
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if keyword in line:
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    return "\n".join(lines[start:end])
            return ""
        except Exception as e:
            logger.error(f"Error extracting code snippet: {e}")
            return ""

    async def regex_checks(self, content, file_path, file_content_lower):
        vulnerabilities = []
        try:
            for check in self.checks:
                for pattern in check["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Format and send vulnerability
                        await self.create_vulnerability_payload(content,
                            file_path,
                            check["category"],
                            check["issue"],
                            check["severity"],
                            f"Pattern match for {check['issue']}",
                        )
                        break
        except Exception as e:
            logger.error(f"Error during regex checks: {e}")
        return vulnerabilities

    async def ast_analysis_python(self, content, file_path):
        vulnerabilities = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    func_name = node.func.id.lower()
                    if func_name in ["md5", "sha1", "des", "rc4"]:
                        await self.create_vulnerability_payload(content,
                            file_path,
                            "Cryptographic Weakness",
                            func_name,
                            "HIGH",
                            f"Use of deprecated or insecure function: {func_name}",
                            line_number=self.find_line_number(content, func_name),
                            recommended_algorithm="SHA-256 or SHA-3"
                        )
        except SyntaxError as e:
            logger.error(f"Syntax error in {file_path}, skipping AST analysis: {e}")
        except Exception as e:
            logger.error(f"Error during Python AST analysis: {e}")
        return vulnerabilities

    async def ast_analysis_java(self, content, file_path):
        vulnerabilities = []
        try:
            tree = javalang.parse.parse(content)
            for path, node in tree:
                if isinstance(node, javalang.tree.MethodInvocation):
                    method_name = node.member.lower()
                    if method_name in ["md5", "sha1", "des", "rc4"]:
                        await self.create_vulnerability_payload(content,
                            file_path,
                            "Cryptographic Weakness",
                            method_name,
                            "HIGH",
                            f"Use of deprecated or insecure function: {method_name}",
                            line_number=self.find_line_number(content, method_name),
                            recommended_algorithm="SHA-256 or SHA-3"
                        )
        except Exception as e:
            logger.error(f"Error parsing Java file {file_path}: {e}")
        return vulnerabilities

    async def ast_analysis_javascript(self, content, file_path):
        vulnerabilities = []
        try:
            tree = esprima.parseScript(content, {"tolerant": True})
            for node in tree.body:
                if node.type == "CallExpression" and node.callee.type == "Identifier":
                    func_name = node.callee.name.lower()
                    if func_name in ["md5", "sha1", "des", "rc4"]:
                        await self.create_vulnerability_payload(content,
                            file_path,
                            "Cryptographic Weakness",
                            func_name,
                            "HIGH",
                            f"Use of deprecated or insecure function: {func_name}",
                            line_number=self.find_line_number(content, func_name),
                            recommended_algorithm="SHA-256 or SHA-3"
                        )
        except Exception as e:
            logger.error(f"Error parsing JavaScript/TypeScript file {file_path}: {e}")
        return vulnerabilities

    async def ast_analysis_php(self, content, file_path):
        vulnerabilities = []
        try:
            tree = phply.phplex.lexer.lex(content)
            for node in tree:
                if node[0] == "T_STRING" and node[1].lower() in [
                    "md5",
                    "sha1",
                    "des",
                    "rc4",
                ]:
                    await self.create_vulnerability_payload(content,
                        file_path,
                        "Cryptographic Weakness",
                        node[1],
                        "HIGH",
                        f"Use of deprecated or insecure function: {node[1]}",
                        line_number=self.find_line_number(content, node[1]),
                        recommended_algorithm="SHA-256 or SHA-3"
                    )
        except Exception as e:
            logger.error(f"Error parsing PHP file {file_path}: {e}")
        return vulnerabilities

    async def entropy_analysis(self, content, file_path):
        vulnerabilities = []
        try:
            high_entropy_strings = detect_high_entropy_strings(content)
            for string in high_entropy_strings:
                await self.create_vulnerability_payload(content,
                    file_path,
                    "Hardcoded Secrets",
                    "High Entropy String",
                    "CRITICAL",
                    f"High entropy string detected: {string}",
                )
        except Exception as e:
            logger.error(f"Error during entropy analysis: {e}")
        return vulnerabilities

    async def certificate_validation(self, content, file_path):
        vulnerabilities = []
        try:
            cert = x509.load_pem_x509_certificate(content.encode(), default_backend())
            if cert.not_valid_after < datetime.now():
                await self.create_vulnerability_payload(content,
                    file_path,
                    "Misconfigurations",
                    "Expired Certificate",
                    "MEDIUM",
                    "Expired certificate detected",
                )
            if cert.issuer == cert.subject:
                await self.create_vulnerability_payload(content,
                    file_path,
                    "Misconfigurations",
                    "Self-Signed Certificate",
                    "MEDIUM",
                    "Self-signed certificate detected",
                )
        except Exception as e:
            logger.error(f"Error validating certificate in {file_path}: {e}")
        return vulnerabilities

    async def library_dependency_checks(self):
        vulnerabilities = []
        try:
            result = subprocess.run(["pip-audit"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "VULNERABLE" in line:
                        await self.create_vulnerability_payload(None,
                            {"path": "requirements.txt"},
                            "Library Dependency",
                            "Vulnerable Package",
                            "HIGH",
                            line.strip(),
                        )
        except FileNotFoundError:
            logger.info("pip-audit not found, skipping library dependency checks.")
        except Exception as e:
            logger.error(f"Error during library dependency checks: {e}")
        return vulnerabilities

    async def ssl_tls_checks(self):
        vulnerabilities = []
        if shutil.which("sslyze"):
            try:
                result = subprocess.run(
                    ["sslyze", "--regular"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if (
                            "SSLv2" in line
                            or "SSLv3" in line
                            or "TLSv1.0" in line
                            or "TLSv1.1" in line
                        ):
                            await self.create_vulnerability_payload(None,
                                {"path": "SSL/TLS Configuration"},
                                "Misconfigurations",
                                "SSL/TLS Weakness",
                                "HIGH",
                                line.strip(),
                            )
            except Exception as e:
                logger.error(f"Error running sslyze: {e}")
        else:
            logger.info("sslyze not found, skipping SSL/TLS checks.")
        return vulnerabilities