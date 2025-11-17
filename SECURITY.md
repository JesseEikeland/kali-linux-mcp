# Security Policy

## Supported Versions

This project is currently in active development. Security updates will be provided for:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within this MCP server, please send an email to the repository owner or open a private security advisory on GitHub.

**Please do NOT open a public issue for security vulnerabilities.**

## Security Best Practices

When using this MCP server:

1. **Authorization**: Always obtain written permission before testing any systems
2. **Isolation**: Use in isolated lab environments whenever possible
3. **Logging**: Review logs regularly for any unexpected activity
4. **Updates**: Keep Docker images and dependencies up to date
5. **Access Control**: Limit access to the MCP server to authorized users only

## Responsible Disclosure

If you discover vulnerabilities using these tools:

1. Document your findings thoroughly
2. Notify the affected system owner privately
3. Allow reasonable time (typically 90 days) for remediation
4. Do not publicly disclose without permission
5. Follow coordinated disclosure practices

## Legal Considerations

Users must:
- Comply with all applicable laws in their jurisdiction
- Have explicit authorization before testing any systems
- Accept full responsibility for their actions
- Not use these tools for malicious purposes

## Security Features

This MCP server includes:
- Input sanitization to prevent command injection
- Non-root container execution
- Command timeout protection
- IP and domain validation
- Comprehensive logging
- Dangerous character filtering

## Disclaimer

The authors and contributors are not responsible for misuse of these tools. Users are solely responsible for ensuring they have proper authorization before testing any systems.