# Automated SAST & Hardcoded Secret Scanner

A lightweight Static Application Security Testing (SAST) and Secret Detection tool built in Python. Designed to identify exposed API keys, hardcoded credentials, and dangerous code patterns in source code before deployment.

## Features

- **Secret Detection**: Identifies exposed AWS keys, Stripe API tokens, generic passwords, and private keys.
- **SAST Capabilities**: Flags dangerous coding patterns like Command Injection risks (`os.system`) and unsafe `eval/exec` calls.
- **CI/CD Ready**: Returns proper exit codes (`exit status 1` on vulnerability detection) to block pipeline builds on security failure.
- **Structured Export**: Outputs results in clean CLI tables or structured JSON files.

## Installation

```bash
git clone [https://github.com/Akinyaman2991/devsecops-secret-scanner.git](https://github.com/Akinyaman2991/devsecops-secret-scanner.git)
cd devsecops-secret-scanner
pip install -r requirements.txt
