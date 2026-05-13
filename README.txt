Project Title:
Cloud Login Monitoring and Suspicious Access Alerts

Project Description:
This project is a cloud-based login monitoring system that detects suspicious login activity using AWS services. A user enters a username and password through a simple frontend page. The request is sent to AWS API Gateway, which forwards it to an AWS Lambda function. The Lambda function checks the login attempt, applies suspicious-access rules, stores the result in DynamoDB, writes logs to CloudWatch, and sends an SNS email alert if suspicious behavior is detected.

Cloud Services Used:
- Amazon API Gateway
- AWS Lambda
- Amazon DynamoDB
- Amazon CloudWatch
- Amazon SNS
- AWS IAM

Main Features:
- Login request processing
- Suspicious username detection
- Long input detection
- Repeated failed attempt detection
- DynamoDB record storage
- CloudWatch logging
- SNS email alerts

Prototype Test Credentials:
- Username: yousef
  Password: 123456

- Username: student
  Password: cloud123

Example Suspicious Test:
- Username: admin
  Password: wrong

Suspicious Login Rules:
- Suspicious usernames such as admin, root, test, and guest
- Very long username or password input
- Too many failed login attempts within a short period

Frontend Testing:
The frontend page was tested locally using:
python -m http.server 8000

Then the page was opened in the browser using:
http://localhost:8000/login_test.html

Notes:
This project is a student prototype and is designed to demonstrate cloud integration, monitoring, alerting, and rule-based suspicious access detection.