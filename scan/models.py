from django.db import models

class Scan(models.Model):
    scan_id = models.CharField(max_length=36, unique=True)  
    repo_url = models.URLField()
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending')  # pending, in_progress, completed

    def __str__(self):
        return f"Scan {self.scan_id}"

class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    file_path = models.CharField(max_length=255)
    line_number = models.IntegerField()
    severity = models.CharField(max_length=20)  # HIGH, MEDIUM, LOW
    issue_type = models.CharField(max_length=100)
    issue_category = models.CharField(max_length=100)
    issue_detail = models.JSONField()  # issueDetail as JSON
    recommendation = models.TextField()
    confidence = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Vulnerability in {self.file_path} at line {self.line_number}"