import os

# BAD PRACTICE: Hardcoded secrets!
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_API_KEY = "sk_live_51Mxxxxxxxxxxxxxxxxxxxxx"

def run_user_input(user_command):
    # BAD PRACTICE: Command Injection vulnerability!
    os.system("ping " + user_command)

def connect_db():
    password = "SuperSecretPassword123!"
    print("Connecting to DB...")