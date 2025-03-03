import ast
import asyncio
import json
import os
import re
import shutil
import subprocess
from datetime import datetime

import aiohttp
import esprima
import javalang
import phply
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .utils import calculate_entropy, detect_high_entropy_strings


class RepoScanner:
    def __init__(self, config_path=os.path.join(os.getcwd(), "config.json")):
        self.checks = self.load_config(config_path)

    def load_config(self, config_path):
        with open(config_path, "r") as f:
            config = json.load(f)
        return config.get("checks", [])

    async def get_repo_files(self, repo_url, token):
        # Fetch files from GitHub using the GitHub API
        repo_owner, repo_name = repo_url.split("/")[-2], repo_url.split("/")[-1]
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents"
        headers = {"Authorization": f"token {token}"}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    raise Exception("Failed to fetch repository contents")
                return await response.json()

    async def scan_repo_files(self, repo_files):
        vulnerabilities = []

        async def fetch_file_content(file_url):
            async with aiohttp.ClientSession() as session:
                async with session.get(file_url) as response:
                    if response.status != 200:
                        raise Exception(
                            f"Failed to download file content from {file_url}"
                        )
                    return await response.text()

        # Process each file in the repo asynchronously
        tasks = []
        for file in repo_files:
            if file["type"] == "file":
                task = self.process_file(file, vulnerabilities, fetch_file_content)
                tasks.append(task)

        await asyncio.gather(*tasks)

        vulnerabilities.extend(self.library_dependency_checks())

        # SSL/TLS Checking (run once for the entire repo)
        vulnerabilities.extend(self.ssl_tls_checks())

        return vulnerabilities

    async def process_file(self, file, vulnerabilities, fetch_file_content):
        content = await fetch_file_content(file["download_url"])
        file_content_lower = content.lower()

        # Regex-based checks
        vulnerabilities.extend(self.regex_checks(content, file["name"]))

        # AST Parsing
        if file["name"].endswith(".py"):
            vulnerabilities.extend(self.ast_analysis_python(content, file["name"]))
        elif file["name"].endswith(".java"):
            vulnerabilities.extend(self.ast_analysis_java(content, file["name"]))
        elif file["name"].endswith((".js", ".ts")):
            vulnerabilities.extend(self.ast_analysis_javascript(content, file["name"]))
        elif file["name"].endswith(".php"):
            vulnerabilities.extend(self.ast_analysis_php(content, file["name"]))

        # Check for hardcoded secrets
        vulnerabilities.extend(self.entropy_analysis(content, file["name"]))

        # Certificate Validation (if file is a certificate)
        if file["name"].endswith((".crt", ".pem")):
            vulnerabilities.extend(self.certificate_validation(content, file["name"]))

    def regex_checks(self, content, file_name):
        vulnerabilities = []
        for check in self.checks:
            for pattern in check["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append(
                        {
                            "file": file_name,
                            "category": check["category"],
                            "issue": check["issue"],
                            "severity": check["severity"],
                        }
                    )
                    break
        return vulnerabilities

    def ast_analysis_python(self, content, file_name):
        vulnerabilities = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    func_name = node.func.id.lower()
                    if func_name in ["md5", "sha1", "des", "rc4"]:
                        vulnerabilities.append(
                            {
                                "file": file_name,
                                "category": "Cryptographic Weakness",
                                "issue": f"Use of deprecated or insecure function: {func_name}",
                                "severity": "HIGH",
                            }
                        )
        except SyntaxError:
            print(f"Syntax error in {file_name}, skipping AST analysis.")
        return vulnerabilities

    def ast_analysis_java(self, content, file_name):
        vulnerabilities = []
        try:
            tree = javalang.parse.parse(content)
            for path, node in tree:
                if isinstance(node, javalang.tree.MethodInvocation):
                    method_name = node.member.lower()
                    if method_name in ["md5", "sha1", "des", "rc4"]:
                        vulnerabilities.append(
                            {
                                "file": file_name,
                                "category": "Cryptographic Weakness",
                                "issue": f"Use of deprecated or insecure function: {method_name}",
                                "severity": "HIGH",
                            }
                        )
        except Exception as e:
            print(f"Error parsing Java file {file_name}: {e}")
        return vulnerabilities

    def ast_analysis_javascript(self, content, file_name):
        vulnerabilities = []
        try:
            tree = esprima.parseScript(content, {"tolerant": True})
            for node in tree.body:
                if node.type == "CallExpression" and node.callee.type == "Identifier":
                    func_name = node.callee.name.lower()
                    if func_name in ["md5", "sha1", "des", "rc4"]:
                        vulnerabilities.append(
                            {
                                "file": file_name,
                                "category": "Cryptographic Weakness",
                                "issue": f"Use of deprecated or insecure function: {func_name}",
                                "severity": "HIGH",
                            }
                        )
        except Exception as e:
            print(f"Error parsing JavaScript/TypeScript file {file_name}: {e}")
        return vulnerabilities

    def ast_analysis_php(self, content, file_name):
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
                    vulnerabilities.append(
                        {
                            "file": file_name,
                            "category": "Cryptographic Weakness",
                            "issue": f"Use of deprecated or insecure function: {node[1]}",
                            "severity": "HIGH",
                        }
                    )
        except Exception as e:
            print(f"Error parsing PHP file {file_name}: {e}")
        return vulnerabilities

    def entropy_analysis(self, content, file_name):
        vulnerabilities = []
        high_entropy_strings = detect_high_entropy_strings(content)
        for string in high_entropy_strings:
            vulnerabilities.append(
                {
                    "file": file_name,
                    "category": "Hardcoded Secrets",
                    "issue": f"High entropy string detected: {string}",
                    "severity": "CRITICAL",
                }
            )
        return vulnerabilities

    def certificate_validation(self, content, file_name):
        vulnerabilities = []
        try:
            cert = x509.load_pem_x509_certificate(content.encode(), default_backend())
            if cert.not_valid_after < datetime.now():
                vulnerabilities.append(
                    {
                        "file": file_name,
                        "category": "Misconfigurations",
                        "issue": "Expired certificate",
                        "severity": "MEDIUM",
                    }
                )
            if cert.issuer == cert.subject:
                vulnerabilities.append(
                    {
                        "file": file_name,
                        "category": "Misconfigurations",
                        "issue": "Self-signed certificate",
                        "severity": "MEDIUM",
                    }
                )
        except Exception as e:
            print(f"Error validating certificate in {file_name}: {e}")
        return vulnerabilities

    def library_dependency_checks(self):
        vulnerabilities = []
        try:
            result = subprocess.run(["pip-audit"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "VULNERABLE" in line:
                        vulnerabilities.append(
                            {
                                "file": "requirements.txt",
                                "category": "Library Dependency",
                                "issue": line.strip(),
                                "severity": "HIGH",
                            }
                        )
        except FileNotFoundError:
            print("pip-audit not found, skipping library dependency checks.")
        return vulnerabilities

    def ssl_tls_checks(self):
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
                            vulnerabilities.append(
                                {
                                    "file": "SSL/TLS Configuration",
                                    "category": "Misconfigurations",
                                    "issue": line.strip(),
                                    "severity": "HIGH",
                                }
                            )
            except Exception as e:
                print(f"Error running sslyze: {e}")
        else:
            print("sslyze not found, skipping SSL/TLS checks.")
        return vulnerabilities
