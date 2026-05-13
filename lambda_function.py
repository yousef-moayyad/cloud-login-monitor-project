import json
import os
import uuid
from datetime import datetime, timezone, timedelta

import boto3

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

table = dynamodb.Table(os.environ["TABLE_NAME"])
TOPIC_ARN = os.environ["TOPIC_ARN"]

SUSPICIOUS_USERNAMES = {"admin", "root", "test", "guest"}
MAX_FAILED_ATTEMPTS = 3
SHORT_WINDOW_MINUTES = 5


def build_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "OPTIONS,POST"
        },
        "body": json.dumps(body)
    }


def lambda_handler(event, context):
    try:
        request_context = event.get("requestContext", {})
        http_info = request_context.get("http", {})
        method = http_info.get("method", "")

        if method == "OPTIONS":
            return build_response(200, {"message": "CORS preflight OK"})

        body = json.loads(event.get("body", "{}"))

        username = body.get("username", "").strip()
        password = body.get("password", "").strip()

        source_ip = http_info.get("sourceIp", "unknown")

        now = datetime.now(timezone.utc)
        status = "FAILED"
        reasons = []

        # Very simple prototype credentials
        valid_users = {
            "yousef": "123456",
            "student": "cloud123"
        }

        # Check suspicious username
        if username.lower() in SUSPICIOUS_USERNAMES:
            reasons.append("Suspicious username")

        # Check long input
        if len(username) > 30 or len(password) > 30:
            reasons.append("Very long input")

        # Simple login check
        if username in valid_users and valid_users[username] == password:
            status = "SUCCESS"

        # Look at old attempts (simple scan for prototype)
        response = table.scan()
        items = response.get("Items", [])

        recent_failed_count = 0
        for item in items:
            if item.get("username") == username and item.get("status") == "FAILED":
                try:
                    old_time = datetime.fromisoformat(item["timestamp"])
                    if now - old_time <= timedelta(minutes=SHORT_WINDOW_MINUTES):
                        recent_failed_count += 1
                except Exception:
                    pass

        if recent_failed_count >= MAX_FAILED_ATTEMPTS:
            reasons.append("Too many failed attempts in short time")

        suspicious = len(reasons) > 0

        item = {
            "attempt_id": str(uuid.uuid4()),
            "username": username,
            "status": status,
            "reason": "; ".join(reasons) if reasons else "Normal login behavior",
            "source_ip": source_ip,
            "timestamp": now.isoformat(),
            "suspicious": suspicious
        }

        table.put_item(Item=item)

        if suspicious:
            sns.publish(
                TopicArn=TOPIC_ARN,
                Subject="Suspicious login detected",
                Message=(
                    f"Suspicious login detected.\n\n"
                    f"Username: {username}\n"
                    f"Status: {status}\n"
                    f"Reason: {item['reason']}\n"
                    f"Source IP: {source_ip}\n"
                    f"Time: {now.isoformat()}"
                )
            )

        return build_response(200, {
            "message": "Login processed",
            "login_status": status,
            "suspicious": suspicious,
            "reason": item["reason"]
        })

    except Exception as e:
        print(str(e))
        return build_response(500, {"message": "Internal server error"})
