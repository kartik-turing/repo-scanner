from rest_framework import serializers


class ScanRequestSerializer(serializers.Serializer):
    repo_url = serializers.URLField()

    class Meta:
        fields = ["repo_url"]

    def validate(self, value):
        if not value["repo_url"].startswith("http"):
            raise serializers.ValidationError("Invalid URL")
        return value
