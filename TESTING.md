# Testing Guide for Nmap Scanner Plugin

## ⚠️ Legal and Ethical Considerations

**IMPORTANT**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal and can result in serious legal consequences.

## 🧪 Safe Testing Environments

### 1. Local Testing (Recommended for Beginners)

Test against your own local network and devices:

```yaml
# Scan your localhost
Target: 127.0.0.1
Ports: 80,443,8080

# Scan your local subnet (ensure you own all devices)
Target: 192.168.1.0/24
Discovery Method: arp
```

### 2. Purpose-Built Test Targets

Several organizations provide legal targets for testing:

#### Scanme.nmap.org
- **Host**: scanme.nmap.org
- **Purpose**: Official Nmap test host
- **Limitations**: Be respectful, don't overload

```yaml
Target: scanme.nmap.org
Ports: 22,80,443
Scan Type: tcp_connect
```

#### Metasploitable
- Download and run in a VM: https://sourceforge.net/projects/metasploitable/
- Intentionally vulnerable Linux for testing

#### DVWA (Damn Vulnerable Web Application)
- Docker: `docker run --rm -it -p 80:80 vulnerables/web-dvwa`
- Test web vulnerability scanning features

### 3. Cloud Testing Environments

Create isolated test environments:

```bash
# AWS EC2 Instance (your own)
Target: your-ec2-instance.amazonaws.com

# Digital Ocean Droplet (your own)
Target: your-droplet-ip

# Azure VM (your own)
Target: your-azure-vm.cloudapp.azure.com
```

## 📋 Test Cases

### Basic Functionality Tests

#### Test 1: Simple Port Scan
```yaml
Tool: port_scanner
Parameters:
  targets: "127.0.0.1"
  ports: "22,80,443"
  scan_type: "tcp_connect"
Expected: List of open/closed ports
```

#### Test 2: Service Detection
```yaml
Tool: service_detector
Parameters:
  target: "scanme.nmap.org"
  ports: "1-100"
  intensity: 7
Expected: Service names and versions
```

#### Test 3: Network Discovery
```yaml
Tool: network_discovery
Parameters:
  network: "192.168.1.0/24"
  discovery_method: "arp"
Expected: List of active hosts
```

### Advanced Tests

#### Test 4: Vulnerability Scanning
```yaml
Tool: vulnerability_scanner
Parameters:
  target: "metasploitable-vm"
  scan_level: "safe"
  vulnerability_types: "common"
Expected: List of potential vulnerabilities
```

#### Test 5: OS Detection
```yaml
Tool: os_fingerprint
Parameters:
  target: "test-host"
  aggressive_guess: true
Expected: OS identification results
```

### Performance Tests

#### Test 6: Timing Templates
Test different timing settings:
```yaml
# Slow and stealthy
timing_template: "sneaky"
max_parallelism: 10

# Fast scanning
timing_template: "aggressive"
max_parallelism: 500
```

#### Test 7: Large Network Scan
```yaml
# Only on networks you own!
Target: "10.0.0.0/24"
Ports: "common"
Timing: "normal"
```

## 🔬 Unit Testing

### Python Test Suite

Create `test_nmap_plugin.py`:

```python
import unittest
from unittest.mock import Mock, patch
from tools.port_scanner import PortScanner, ToolParameters

class TestNmapPlugin(unittest.TestCase):
    
    def setUp(self):
        self.scanner = PortScanner()
    
    def test_parameter_validation(self):
        """Test parameter validation"""
        params = ToolParameters(
            targets="192.168.1.1",
            ports="1-1000",
            scan_type="tcp_connect"
        )
        self.assertEqual(params.targets, "192.168.1.1")
        self.assertEqual(params.scan_type, "tcp_connect")
    
    def test_invalid_ports(self):
        """Test invalid port specification"""
        with self.assertRaises(ValueError):
            ToolParameters(
                targets="192.168.1.1",
                ports="invalid-ports"
            )
    
    @patch('nmap.PortScanner')
    def test_scan_execution(self, mock_nmap):
        """Test scan execution"""
        mock_scanner = Mock()
        mock_nmap.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'scan': {
                '127.0.0.1': {
                    'tcp': {
                        80: {'state': 'open', 'name': 'http'}
                    }
                }
            }
        }
        
        # Execute scan
        results = list(self.scanner._invoke({
            'targets': '127.0.0.1',
            'ports': '80'
        }))
        
        # Verify results
        self.assertTrue(len(results) > 0)

if __name__ == '__main__':
    unittest.main()
```

Run tests:
```bash
python -m pytest test_nmap_plugin.py -v
```

## 🔍 Integration Testing

### Test with Dify

1. **Install Plugin**:
   ```bash
   # Package the plugin
   zip -r nmap-scanner.zip . -x "*.git*" -x "*__pycache__*"
   
   # Upload to Dify
   ```

2. **Test Basic Workflow**:
   - Create a new workflow in Dify
   - Add the Nmap Scanner tool
   - Configure with safe parameters
   - Execute and verify results

3. **Test Error Handling**:
   - Invalid targets
   - Unreachable hosts
   - Permission errors
   - Timeout scenarios

## 📊 Performance Benchmarks

### Benchmark Different Configurations

```python
import time
import statistics

def benchmark_scan(target, ports, timing):
    start = time.time()
    # Execute scan
    result = scanner.scan(target, ports, timing)
    end = time.time()
    return end - start

# Test different configurations
configs = [
    ("127.0.0.1", "1-100", "normal"),
    ("127.0.0.1", "1-1000", "normal"),
    ("127.0.0.1", "1-100", "aggressive"),
]

for target, ports, timing in configs:
    times = []
    for _ in range(5):
        duration = benchmark_scan(target, ports, timing)
        times.append(duration)
    
    print(f"Config: {target}:{ports} ({timing})")
    print(f"  Average: {statistics.mean(times):.2f}s")
    print(f"  Std Dev: {statistics.stdev(times):.2f}s")
```

## 🐛 Debugging

### Enable Debug Mode

Set in `.env`:
```bash
DEBUG_MODE=true
LOG_LEVEL=DEBUG
VERBOSE=true
NMAP_DEBUG=true
```

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| "Nmap not found" | Install Nmap: `apt-get install nmap` |
| "Permission denied" | Use TCP connect scan or run with sudo |
| "Host seems down" | Try with `-Pn` (no_ping=true) |
| "Scan too slow" | Increase timing template, reduce ports |
| "No results" | Check firewall, verify target is reachable |

### Debug Output Analysis

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Capture Nmap output
nm = nmap.PortScanner()
nm.scan('127.0.0.1', '80', arguments='-v -d')
print(nm.command_line())  # See exact command
print(nm.stdout)          # Raw output
```

## 🔒 Security Testing

### Test Security Features

1. **Test Rate Limiting**:
   ```python
   # Should be limited by MAX_CONCURRENT_SCANS
   for i in range(10):
       scanner.scan(f"192.168.1.{i}", "80")
   ```

2. **Test Input Sanitization**:
   ```python
   # Should sanitize dangerous input
   dangerous_inputs = [
       "127.0.0.1; rm -rf /",
       "127.0.0.1 && cat /etc/passwd",
       "../../../etc/passwd"
   ]
   ```

3. **Test Blocked Networks**:
   ```python
   # Should block if configured
   blocked = ["127.0.0.0/8", "169.254.0.0/16"]
   ```

## 📈 Load Testing

### Stress Test the Plugin

```python
import concurrent.futures
import threading

def stress_test(num_scans=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for i in range(num_scans):
            future = executor.submit(
                scanner.scan,
                "127.0.0.1",
                f"{i+1}-{i+100}"
            )
            futures.append(future)
        
        results = [f.result() for f in futures]
        return results
```

## ✅ Testing Checklist

Before deployment, ensure:

- [ ] All unit tests pass
- [ ] Integration tests complete
- [ ] Security features verified
- [ ] Rate limiting works
- [ ] Error handling tested
- [ ] Performance acceptable
- [ ] Memory usage stable
- [ ] Logs properly formatted
- [ ] Documentation accurate
- [ ] Legal compliance verified

## 📝 Test Report Template

```markdown
# Nmap Scanner Plugin Test Report

**Date**: [Date]
**Version**: [Version]
**Tester**: [Name]

## Test Environment
- OS: [Operating System]
- Python: [Version]
- Nmap: [Version]
- Dify: [Version]

## Test Results

### Functional Tests
| Test Case | Result | Notes |
|-----------|--------|-------|
| Port Scan | ✅ Pass | |
| Service Detection | ✅ Pass | |
| OS Detection | ⚠️ Warning | Requires root |
| Vulnerability Scan | ✅ Pass | |

### Performance Tests
- Average scan time: X seconds
- Memory usage: X MB
- CPU usage: X%

### Security Tests
- Input validation: ✅ Pass
- Rate limiting: ✅ Pass
- Authorization: ✅ Pass

## Issues Found
1. [Issue description]
2. [Issue description]

## Recommendations
- [Recommendation]
- [Recommendation]

## Sign-off
- [ ] Ready for production
- [ ] Requires fixes
```

## 🚀 Continuous Testing

Set up automated testing:

```yaml
# .github/workflows/test.yml
name: Plugin Tests

on: [ push, pull_request ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Nmap
        run: sudo apt-get install -y nmap
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python -m pytest tests/ -v
```

---

**Remember**: Always test responsibly and legally. When in doubt, use your own systems or purpose-built testing environments.