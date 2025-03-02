import re
import ast
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import shutil
import javalang
import esprima
import phply
from utils import calculate_entropy, detect_high_entropy_strings

class RepoScanner:
    def __init__(self, config_path="repo_scanner/config.json"):
        self.checks = self.load_config(config_path)

    def load_config(self, config_path):
        with open(config_path, "r") as f:
            config = json.load(f)
        return config.get("checks", [])

    def scan_repo_files(self, repo_files):
        vulnerabilities = []
        for file in repo_files:
            if file['type'] == 'file':
                content = requests.get(file['download_url']).text
                file_content_lower = content.lower()

                # Regex-based checks
                vulnerabilities.extend(self.regex_checks(content, file['name']))

                # AST Parsing for multiple languages
                if file['name'].endswith('.py'):
                    vulnerabilities.extend(self.ast_analysis_python(content, file['name']))
                elif file['name'].endswith('.java'):
                    vulnerabilities.extend(self.ast_analysis_java(content, file['name']))
                elif file['name'].endswith(('.js', '.ts')):
                    vulnerabilities.extend(self.ast_analysis_javascript(content, file['name']))
                elif file['name'].endswith('.php'):
                    vulnerabilities.extend(self.ast_analysis_php(content, file['name']))

                # Entropy Analysis for hardcoded secrets
                vulnerabilities.extend(self.entropy_analysis(content, file['name']))

                # Certificate Validation (if file is a certificate)
                if file['name'].endswith(('.crt', '.pem')):
                    vulnerabilities.extend(self.certificate_validation(content, file['name']))

        # Library Dependency Checks (run once for the entire repo)
        vulnerabilities.extend(self.library_dependency_checks())

        # SSL/TLS Checking (run once for the entire repo)
        vulnerabilities.extend(self.ssl_tls_checks())

        return vulnerabilities

    def regex_checks(self, content, file_name):
        vulnerabilities = []
        for check in self.checks:
            for pattern in check['patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append({
                        'file': file_name,
                        'category': check['category'],
                        'issue': check['issue'],
                        'severity': check['severity'],
                    })
                    break  # Stop checking other patterns for this issue if one is found
        return vulnerabilities

    def ast_analysis_python(self, content, file_name):
        vulnerabilities = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    func_name = node.func.id.lower()
                    if func_name in ['md5', 'sha1', 'des', 'rc4']:
                        vulnerabilities.append({
                            'file': file_name,
                            'category': 'Cryptographic Weakness',
                            'issue': f'Use of deprecated or insecure function: {func_name}',
                            'severity': 'HIGH',
                        })
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
                    if method_name in ['md5', 'sha1', 'des', 'rc4']:
                        vulnerabilities.append({
                            'file': file_name,
                            'category': 'Cryptographic Weakness',
                            'issue': f'Use of deprecated or insecure function: {method_name}',
                            'severity': 'HIGH',
                        })
        except Exception as e:
            print(f"Error parsing Java file {file_name}: {e}")
        return vulnerabilities

    def ast_analysis_javascript(self, content, file_name):
        vulnerabilities = []
        try:
            tree = esprima.parseScript(content, {'tolerant': True})
            for node in tree.body:
                if node.type == 'CallExpression' and node.callee.type == 'Identifier':
                    func_name = node.callee.name.lower()
                    if func_name in ['md5', 'sha1', 'des', 'rc4']:
                        vulnerabilities.append({
                            'file': file_name,
                            'category': 'Cryptographic Weakness',
                            'issue': f'Use of deprecated or insecure function: {func_name}',
                            'severity': 'HIGH',
                        })
        except Exception as e:
            print(f"Error parsing JavaScript/TypeScript file {file_name}: {e}")
        return vulnerabilities

    def ast_analysis_php(self, content, file_name):
        vulnerabilities = []
        try:
            tree = phply.phplex.lexer.lex(content)
            for node in tree:
                if node[0] == 'T_STRING' and node[1].lower() in ['md5', 'sha1', 'des', 'rc4']:
                    vulnerabilities.append({
                        'file': file_name,
                        'category': 'Cryptographic Weakness',
                        'issue': f'Use of deprecated or insecure function: {node[1]}',
                        'severity': 'HIGH',
                    })
        except Exception as e:
            print(f"Error parsing PHP file {file_name}: {e}")
        return vulnerabilities

    def entropy_analysis(self, content, file_name):
        vulnerabilities = []
        high_entropy_strings = detect_high_entropy_strings(content)
        for string in high_entropy_strings:
            vulnerabilities.append({
                'file': file_name,
                'category': 'Hardcoded Secrets',
                'issue': f'High entropy string detected: {string}',
                'severity': 'CRITICAL',
            })
        return vulnerabilities

    def certificate_validation(self, content, file_name):
        vulnerabilities = []
        try:
            cert = x509.load_pem_x509_certificate(content.encode(), default_backend())
            if cert.not_valid_after < datetime.now():
                vulnerabilities.append({
                    'file': file_name,
                    'category': 'Misconfigurations',
                    'issue': 'Expired certificate',
                    'severity': 'MEDIUM',
                })
            if cert.issuer == cert.subject:
                vulnerabilities.append({
                    'file': file_name,
                    'category': 'Misconfigurations',
                    'issue': 'Self-signed certificate',
                    'severity': 'MEDIUM',
                })
        except Exception as e:
            print(f"Error validating certificate in {file_name}: {e}")
        return vulnerabilities

    def library_dependency_checks(self):
        vulnerabilities = []
        try:
            result = subprocess.run(['pip-audit'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'VULNERABLE' in line:
                        vulnerabilities.append({
                            'file': 'requirements.txt',
                            'category': 'Library Dependency',
                            'issue': line.strip(),
                            'severity': 'HIGH',
                        })
        except FileNotFoundError:
            print("pip-audit not found, skipping library dependency checks.")
        return vulnerabilities

    def ssl_tls_checks(self):
        vulnerabilities = []
        if shutil.which('sslyze'):
            try:
                result = subprocess.run(['sslyze', '--regular'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'SSLv2' in line or 'SSLv3' in line or 'TLSv1.0' in line or 'TLSv1.1' in line:
                            vulnerabilities.append({
                                'file': 'SSL/TLS Configuration',
                                'category': 'Misconfigurations',
                                'issue': line.strip(),
                                'severity': 'HIGH',
                            })
            except Exception as e:
                print(f"Error running sslyze: {e}")
        else:
            print("sslyze not found, skipping SSL/TLS checks.")
        return vulnerabilities