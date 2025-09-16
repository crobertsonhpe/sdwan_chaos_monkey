# SD-WAN Chaos Monkey

A chaos engineering tool for testing SD-WAN network resilience by systematically introducing controlled interface failures and validating recovery capabilities.

## Overview

The SD-WAN Chaos Monkey is inspired by Netflix's original Chaos Monkey and applies chaos engineering principles to SD-WAN infrastructure. It automatically discovers your Silver Peak/Aruba EdgeConnect appliances, identifies WAN interfaces, and performs controlled failover tests to validate network resilience.

## Features

- 🔍 **Automatic Discovery** - Discovers all SD-WAN appliances and WAN interfaces
- 🎯 **Systematic Testing** - Cycles through interfaces in a controlled manner
- ⏱️ **Configurable Chaos** - Customizable failure duration and test intervals
- 🔄 **Recovery Validation** - Verifies interfaces return to operational state
- 📊 **Comprehensive Reporting** - Detailed metrics and per-appliance statistics
- 🔐 **Flexible Authentication** - Supports API tokens and basic authentication
- 🛡️ **Safety Features** - Built-in safeguards and error handling

## Installation

### Prerequisites

- Python 3.7 or higher
- Network access to Silver Peak/Aruba EdgeConnect Orchestrator
- Valid API credentials (token or username/password)

### Setup

1. **Clone or download the script:**
   ```bash
   wget https://example.com/sdwan_chaos_monkey.py
   # or copy the script file to your system
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make executable (optional):**
   ```bash
   chmod +x sdwan_chaos_monkey.py
   ```

## Quick Start

### Basic Usage with API Token

```bash
python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --url https://your-orchestrator.com
```

### Run Single Interface Test

```bash
python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --single-test 4.NE twan0
```

### Run Limited Cycles with Custom Timing

```bash
python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --cycles 5 --duration 60 --wait 120
```

## Command Line Options

### Authentication (Required - Choose One)

- `--token TOKEN` - API token for authentication (recommended)
- `--auth USERNAME:PASSWORD` - Basic authentication credentials

### Basic Configuration

- `--url URL` - Orchestrator base URL (default: pre-configured)
- `--duration SECONDS` - Interface chaos duration (default: 30)
- `--cycles N` - Number of test cycles (default: infinite)
- `--wait SECONDS` - Wait time between cycles (default: 300 = 5 minutes)

### Test Modes

- `--single-test NEPK INTERFACE` - Test specific appliance/interface
- Default: Continuous cycling through all discovered WAN interfaces

### Advanced Options

- `--query-auth` - Use apiKey query parameter instead of X-Auth-Token header
- `--no-verify-ssl` - Disable SSL certificate verification
- `--timeout SECONDS` - HTTP request timeout (default: 30)
- `--debug` - Enable detailed debug logging

## Usage Examples

### Continuous Chaos Testing

Run indefinitely, testing each WAN interface for 45 seconds with 10-minute intervals:

```bash
python3 sdwan_chaos_monkey.py \
    --token YOUR_TOKEN \
    --url https://orchestrator.example.com \
    --duration 45 \
    --wait 600
```

### Limited Test Campaign

Run exactly 20 chaos events with 2-minute disruptions:

```bash
python3 sdwan_chaos_monkey.py \
    --token YOUR_TOKEN \
    --cycles 20 \
    --duration 120
```

### Single Interface Validation

Test a specific interface on a known appliance:

```bash
python3 sdwan_chaos_monkey.py \
    --token YOUR_TOKEN \
    --single-test 4.NE twan0
```

### Debug Mode with Basic Auth

Run with detailed logging using username/password authentication:

```bash
python3 sdwan_chaos_monkey.py \
    --auth admin:password \
    --url https://orchestrator.example.com \
    --debug \
    --no-verify-ssl
```

## How It Works

### Discovery Phase

1. **Connects** to Silver Peak/Aruba EdgeConnect Orchestrator
2. **Enumerates** all managed SD-WAN appliances
3. **Retrieves** deployment configurations for each appliance
4. **Identifies** WAN-side interfaces (excludes link-local addresses)
5. **Builds** test target inventory

### Chaos Testing Phase

1. **Selects** next interface in rotation
2. **Validates** interface is initially operational
3. **Administratively disables** the interface (chaos event)
4. **Waits** for specified chaos duration
5. **Re-enables** the interface
6. **Verifies** operational recovery
7. **Records** results and metrics

### Reporting

- Real-time progress logging
- Per-test summaries with timing metrics
- Final comprehensive report including:
  - Overall success/failure rates
  - Per-appliance resilience statistics
  - Performance metrics (min/max/avg chaos duration)

## Understanding the Output

### Test Progress

```
============================================================
CHAOS EVENT: twan0 (MPLS-Primary) on Branch-Office-NYC
Chaos Duration: 30 seconds
============================================================
Setting twan0 (MPLS-Primary) to DOWN on Branch-Office-NYC...
Successfully set twan0 (MPLS-Primary) to DOWN
Introducing chaos for 30 seconds...
   30 seconds of chaos remaining...
   20 seconds of chaos remaining...
   10 seconds of chaos remaining...
   5 seconds of chaos remaining...
Setting twan0 (MPLS-Primary) to UP on Branch-Office-NYC...
Successfully set twan0 (MPLS-Primary) to UP
Verifying twan0 (MPLS-Primary) is operational on Branch-Office-NYC...
Interface twan0 (MPLS-Primary) is operational
```

### Final Summary

```
================================================================================
SD-WAN CHAOS MONKEY - FINAL SUMMARY
================================================================================
Total Chaos Events: 12
Successful Recoveries: 11
Failed Recoveries: 1
Recovery Success Rate: 91.7%

Per-Appliance Resilience Results:
   Branch-Office-NYC: 4/4 (100.0% recovery rate) - Avg chaos duration: 32.1s
   Branch-Office-LA: 3/4 (75.0% recovery rate) - Avg chaos duration: 28.9s
   HQ-Primary: 4/4 (100.0% recovery rate) - Avg chaos duration: 31.2s

Chaos Engineering Metrics:
   Average chaos duration: 30.7s
   Minimum chaos duration: 28.1s
   Maximum chaos duration: 35.4s
```

## Safety Considerations

### Built-in Safeguards

- **Interface Validation** - Verifies interfaces are operational before testing
- **Recovery Verification** - Ensures interfaces return to service after chaos
- **Error Handling** - Graceful handling of API failures and network issues
- **Controlled Scope** - Only affects administratively down/up states

### Best Practices

- **Start Small** - Begin with single interface tests (`--single-test`)
- **Test Windows** - Run during maintenance windows initially
- **Monitor Impact** - Watch for application/service disruptions
- **Document Results** - Keep records of chaos events and outcomes
- **Gradual Adoption** - Increase chaos frequency over time

### Pre-Test Checklist

- [ ] Verify backup connectivity paths exist
- [ ] Confirm monitoring systems are functional
- [ ] Ensure staff availability for incident response
- [ ] Test during low-impact periods initially
- [ ] Validate orchestrator API access and permissions

## Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# HTTP 401 Unauthorized
ERROR - Authentication failed! Check your token/credentials.
```
**Solution:** Verify your API token is valid and has appropriate permissions.

#### Connection Issues
```bash
# Connection timeout or SSL errors
ERROR - Connection timeout! Check the URL and network connectivity.
```
**Solution:** Verify orchestrator URL, network connectivity, and try `--no-verify-ssl` if needed.

#### No Interfaces Found
```bash
# No WAN interfaces discovered
WARNING - No WAN interfaces found for appliance X
```
**Solution:** Check appliance configurations and ensure WAN interfaces are properly configured.

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
python3 sdwan_chaos_monkey.py --token YOUR_TOKEN --debug
```

### Getting Help

For issues or questions:
1. Run with `--debug` flag for detailed logs
2. Check orchestrator API documentation
3. Verify network connectivity and permissions
4. Review appliance configurations

## Advanced Configuration

### Custom Orchestrator URLs

The tool supports various Orchestrator deployments:

```bash
# Cloud-hosted orchestrator
--url https://customer.silverpeak.cloud

# On-premises deployment
--url https://orchestrator.company.com:8443

# Custom port
--url https://sdwan-orchestrator:9999
```

### API Authentication Methods

Choose the authentication method that matches your environment:

```bash
# Header-based token (default)
--token YOUR_API_TOKEN

# Query parameter token (alternative)
--token YOUR_API_TOKEN --query-auth

# Basic authentication
--auth username:password
```

## License

This chaos engineering tool is provided as-is for network testing and validation purposes. Use responsibly in controlled environments.

## Disclaimer

This tool introduces controlled network disruptions. Always:
- Test in non-production environments first
- Ensure adequate backup connectivity
- Have incident response procedures ready
- Use during planned maintenance windows
- Monitor for unintended consequences

The authors are not responsible for any network outages or service disruptions caused by the use of this tool.
