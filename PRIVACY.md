# Privacy Policy - Nmap Scanner Plugin

## Data Processing

This plugin performs network scanning operations and:

- **Does NOT collect** any user data beyond scan configurations
- **Does NOT store** scan results permanently
- **Does NOT transmit** data to external servers (except target hosts)
- **Does NOT retain** scan history after session ends
- **Does NOT track** usage statistics or telemetry
- **Does NOT share** any information with third parties

## Network Communication

- **Target Communication**: The plugin only communicates with explicitly specified target hosts
- **No Phone Home**: No connections to plugin developer servers
- **Local Processing**: All scan analysis is performed locally
- **No Cloud Services**: Does not use any cloud-based services

## Data Security

- **Memory Only**: Scan results exist only in memory during processing
- **Immediate Disposal**: Data is cleared after each scan completes
- **Credential Protection**: Any provided credentials are encrypted in memory
- **No Persistent Storage**: No databases or files are created
- **Session Isolation**: Each scan session is isolated

## Scan Data

When performing scans, the plugin:

- Temporarily processes target IP addresses and hostnames
- Analyzes port states and service information
- Evaluates security configurations
- All data is discarded after results are returned

## User Responsibilities

Users are responsible for:

- Obtaining proper authorization before scanning
- Complying with all applicable laws
- Protecting scan results containing sensitive information
- Using the tool ethically and responsibly

## Compliance

This plugin is designed to comply with:

- GDPR (General Data Protection Regulation)
- CCPA (California Consumer Privacy Act)
- HIPAA (when used in healthcare environments)
- PCI-DSS (when scanning payment systems)
- Other applicable data protection regulations

## Logging

- **Audit Logs**: Basic scan parameters may be logged for security
- **No Result Storage**: Scan results are never logged
- **Error Reporting**: Only non-sensitive error information is logged
- **User Control**: Logging can be disabled if required

## Third-Party Components

This plugin uses:

- **Nmap**: Open-source network scanner (GPL licensed)
- **python-nmap**: Python wrapper for Nmap
- All third-party components follow their respective privacy policies

## Security Considerations

- **Authorization Required**: Users must have permission to scan targets
- **Legal Compliance**: Users must comply with local laws
- **Ethical Use**: Plugin should only be used for legitimate security testing
- **No Warranty**: Plugin provided as-is without warranty

## Updates

This privacy policy may be updated to reflect:

- Changes in functionality
- New regulatory requirements
- Security improvements
- User feedback

## Contact

For privacy-related inquiries:

- Email: privacy@security-tools.example.com
- GitHub: [Issue Tracker]

## Incident Reporting

If you discover any privacy or security issues:

1. Do not publicly disclose the issue
2. Contact us immediately
3. Provide detailed information
4. Allow time for resolution

## Data Retention

- **Scan Configurations**: Retained only during active session
- **Scan Results**: Immediately discarded after display
- **Credentials**: Cleared from memory after use
- **Error Logs**: Retained for maximum 7 days
- **User Preferences**: Stored locally, never transmitted

## International Users

This plugin:

- Can be used globally
- Complies with international privacy standards
- Does not transfer data across borders
- Respects local privacy regulations

## Children's Privacy

This plugin:

- Is not intended for use by children under 18
- Does not knowingly collect information from minors
- Should be used under adult supervision in educational settings

## Transparency

We are committed to:

- Clear communication about data handling
- Open-source development
- Regular security audits
- Prompt response to privacy concerns

---

**Last Updated**: August 2025
**Version**: 1.0.0
**Effective Date**: Immediately upon installation

By using this plugin, you acknowledge and agree to these privacy practices.