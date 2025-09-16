#!/usr/bin/env python3
"""
SD-WAN Chaos Monkey

A chaos engineering tool for SD-WAN networks that automatically tests interface failover by:
1. Getting all appliances and their NEPK values
2. Getting deployment details for each appliance
3. Extracting WAN interfaces from deployment details
4. Cycling through appliances and WAN interfaces
5. Shutting down interfaces for a period of time (introducing controlled chaos)
6. Bringing up interfaces and validating they are operational
7. Waiting 5 minutes between cycles

This tool helps validate network resilience and failover capabilities by introducing
controlled network disruptions in a systematic way.

Usage:
    python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN [options]
"""

import argparse
import json
import logging
import time
import sys
from datetime import datetime
from typing import Dict, Optional, Tuple, List, Union
from dataclasses import dataclass
from enum import Enum
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuthMethod(Enum):
    """Authentication method enumeration"""
    HEADER_TOKEN = "header_token"
    QUERY_TOKEN = "query_token"
    BASIC_AUTH = "basic_auth"


@dataclass
class WANInterface:
    """WAN interface data structure"""
    nepk: str
    interface_name: str
    label_name: str
    ip_address: str = ""
    
    @property
    def display_name(self) -> str:
        return f"{self.interface_name} ({self.label_name})" if self.label_name else self.interface_name


@dataclass
class TestResult:
    """Test result data structure"""
    cycle: int
    wan_interface: WANInterface
    appliance_name: str
    success: bool
    timestamp: datetime
    downtime_seconds: float = 0.0


@dataclass
class ApplianceInfo:
    """Appliance information data structure"""
    nepk: str
    name: str
    site: str = "Unknown"
    model: str = "Unknown"
    deployment: Optional[Dict] = None
    wan_interfaces: List[WANInterface] = None
    
    def __post_init__(self):
        if self.wan_interfaces is None:
            self.wan_interfaces = []


class SDWANChaosMonkey:
    """SD-WAN Chaos Monkey - Manages controlled chaos testing across multiple SD-WAN appliances"""
    
    # Constants
    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRY_COUNT = 3
    DEFAULT_BACKOFF_FACTOR = 0.3
    LINK_LOCAL_PREFIX = "169.254."
    
    def __init__(self, base_url: str, auth_token: str = None, username: str = None, 
                 password: str = None, failover_duration: int = 30, verify_ssl: bool = True,
                 use_query_auth: bool = False):
        """
        Initialize the SD-WAN Chaos Monkey
        
        Args:
            base_url: Base URL of the orchestrator
            auth_token: API token for authentication (preferred)
            username: Username for basic auth (fallback)
            password: Password for basic auth (fallback)
            failover_duration: Time to wait during chaos event (default: 30 seconds)
            verify_ssl: Whether to verify SSL certificates
            use_query_auth: Use apiKey query parameter instead of X-Auth-Token header
        """
        self.base_url = base_url.rstrip('/')
        self.failover_duration = failover_duration
        self.verify_ssl = verify_ssl
        self.auth_token = auth_token
        
        # Setup authentication method
        self.auth_method = self._determine_auth_method(auth_token, username, password, use_query_auth)
        self.username = username
        self.password = password
        
        # Setup session with retry strategy
        self.session = self._create_session()
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"Base URL: {self.base_url}")
        self.logger.info(f"Authentication method: {self.auth_method.value}")
        
        # Test connectivity
        self._test_connectivity()
        
        # Storage for discovered data
        self.appliances: Dict[str, ApplianceInfo] = {}
        self.wan_interfaces: List[WANInterface] = []
        self.current_test_index = 0
    
    def _determine_auth_method(self, auth_token: str, username: str, password: str, 
                              use_query_auth: bool) -> AuthMethod:
        """Determine the authentication method to use"""
        if auth_token:
            return AuthMethod.QUERY_TOKEN if use_query_auth else AuthMethod.HEADER_TOKEN
        elif username and password:
            return AuthMethod.BASIC_AUTH
        else:
            self.logger.warning("No authentication provided - requests may fail")
            return AuthMethod.BASIC_AUTH
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy and proper configuration"""
        session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=self.DEFAULT_RETRY_COUNT,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=self.DEFAULT_BACKOFF_FACTOR
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Setup headers
        session.headers.update({'Content-Type': 'application/json'})
        
        # Setup authentication
        if self.auth_method == AuthMethod.HEADER_TOKEN and self.auth_token:
            session.headers['X-Auth-Token'] = self.auth_token
        elif self.auth_method == AuthMethod.BASIC_AUTH and self.username and self.password:
            session.auth = HTTPBasicAuth(self.username, self.password)
        
        return session
    
    def _test_connectivity(self):
        """Test basic connectivity to the orchestrator"""
        self.logger.info("Testing connectivity to orchestrator...")
        try:
            response = self._make_request('GET', f"{self.base_url}/gms/rest/appliance", timeout=10)
            
            if response is not None:
                self.logger.info("Connectivity test: SUCCESS")
            else:
                self.logger.error("Connectivity test: FAILED")
                
        except requests.exceptions.RequestException as e:
            self._handle_connection_error(e)
    
    def _handle_connection_error(self, error: Exception):
        """Handle different types of connection errors with specific guidance"""
        if isinstance(error, requests.exceptions.ConnectTimeout):
            self.logger.error("Connection timeout! Check the URL and network connectivity.")
        elif isinstance(error, requests.exceptions.ConnectionError):
            self.logger.error("Connection error! Check the URL and network connectivity.")
        elif isinstance(error, requests.exceptions.SSLError):
            self.logger.error("SSL error! Try using --no-verify-ssl flag.")
        else:
            self.logger.error(f"Connectivity test failed: {error}")
    
    def _build_url_with_auth(self, url: str) -> str:
        """Build URL with query parameter authentication if needed"""
        if self.auth_method == AuthMethod.QUERY_TOKEN and self.auth_token:
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}apiKey={self.auth_token}"
        return url
    
    def _make_request(self, method: str, url: str, data: Dict = None, 
                     timeout: int = None) -> Optional[Union[Dict, List]]:
        """Make HTTP request with proper error handling and response parsing"""
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        
        url = self._build_url_with_auth(url)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, verify=self.verify_ssl, timeout=timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, verify=self.verify_ssl, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return self._parse_response(response)
            
        except requests.exceptions.HTTPError as e:
            self._log_http_error(e)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
        
        return None
    
    def _parse_response(self, response: requests.Response) -> Optional[Union[Dict, List]]:
        """Parse HTTP response with proper error handling"""
        if not response.text:
            return {}
        
        try:
            return response.json()
        except json.JSONDecodeError:
            self.logger.warning(f"Response is not valid JSON: {response.text[:200]}...")
            return {'raw_response': response.text}
    
    def _log_http_error(self, error: requests.exceptions.HTTPError):
        """Log HTTP errors with appropriate detail level"""
        if error.response is not None:
            status_code = error.response.status_code
            self.logger.error(f"HTTP {status_code} error")
            
            if status_code == 401:
                self.logger.error("Authentication failed! Check your token/credentials.")
            elif status_code == 403:
                self.logger.error("Access denied! Check your permissions.")
            elif status_code >= 500:
                self.logger.error("Server error - the orchestrator may be experiencing issues.")
            
            if error.response.text:
                self.logger.debug(f"Response body: {error.response.text[:500]}")
    
    def get_all_appliances(self) -> Dict[str, ApplianceInfo]:
        """Get all appliances and return as ApplianceInfo objects"""
        self.logger.info("Discovering appliances...")
        
        result = self._make_request('GET', f"{self.base_url}/gms/rest/appliance")
        if not result:
            self.logger.error("Failed to retrieve appliances")
            return {}
        
        appliances = {}
        appliance_list = self._extract_appliance_list(result)
        
        for appliance_data in appliance_list:
            nepk = appliance_data.get('nePk')
            if not nepk:
                continue
            
            appliance_info = ApplianceInfo(
                nepk=str(nepk),
                name=appliance_data.get('hostName', f"Appliance-{nepk}"),
                site=appliance_data.get('site', 'Unknown'),
                model=appliance_data.get('model', 'Unknown')
            )
            
            appliances[str(nepk)] = appliance_info
            self.logger.info(f"   Found: {appliance_info.name} (NEPK: {nepk}, Site: {appliance_info.site})")
        
        self.logger.info(f"Total appliances discovered: {len(appliances)}")
        return appliances
    
    def _extract_appliance_list(self, result: Union[Dict, List]) -> List[Dict]:
        """Extract appliance list from API response with various formats"""
        if isinstance(result, list):
            return result
        
        if isinstance(result, dict):
            for key in ['appliances', 'nodes', 'data', 'items']:
                if key in result and isinstance(result[key], list):
                    return result[key]
            
            if 'nePk' in result:
                return [result]
        
        return []
    
    def get_deployment_details(self, nepk: str) -> Optional[Dict]:
        """Get deployment details for a specific appliance"""
        self.logger.debug(f"Getting deployment details for appliance {nepk}...")
        
        url = f"{self.base_url}/gms/rest/deployment?nePk={nepk}"
        result = self._make_request('GET', url)
        
        if result:
            self.logger.debug(f"Successfully retrieved deployment details for {nepk}")
            return result
        
        self.logger.warning(f"Failed to retrieve deployment details for {nepk}")
        return None
    
    def extract_wan_interfaces(self, appliance: ApplianceInfo) -> List[WANInterface]:
        """Extract WAN interfaces from appliance deployment details"""
        if not appliance.deployment:
            self.logger.warning(f"No deployment data for appliance {appliance.nepk}")
            return []
        
        self.logger.debug(f"Extracting WAN interfaces for {appliance.name}...")
        wan_interfaces = []
        
        wan_labels = self._get_wan_labels_mapping(appliance.deployment)
        
        mode_ifs = appliance.deployment.get('modeIfs', [])
        for mode_if in mode_ifs:
            wan_interfaces.extend(
                self._process_interface_ips(mode_if, wan_labels, appliance.nepk)
            )
        
        if not wan_interfaces:
            self.logger.warning(f"No WAN interfaces found for appliance {appliance.name}")
        
        return wan_interfaces
    
    def _get_wan_labels_mapping(self, deployment: Dict) -> Dict[str, str]:
        """Extract WAN label mappings from deployment configuration"""
        sys_config = deployment.get('sysConfig', {})
        if_labels = sys_config.get('ifLabels', {})
        wan_labels = {}
        
        for label in if_labels.get('wan', []):
            label_id = str(label.get('id', ''))
            label_name = label.get('name', '')
            if label_id and label_name:
                wan_labels[label_id] = label_name
        
        return wan_labels
    
    def _process_interface_ips(self, mode_if: Dict, wan_labels: Dict[str, str], 
                              nepk: str) -> List[WANInterface]:
        """Process IP configurations for a single interface"""
        interfaces = []
        if_name = mode_if.get('ifName', '')
        appliance_ips = mode_if.get('applianceIPs', [])
        
        for ip_config in appliance_ips:
            if not ip_config.get('wanSide', False):
                continue
            
            ip_address = ip_config.get('ip', '')
            
            if ip_address.startswith(self.LINK_LOCAL_PREFIX):
                self.logger.debug(f"   Skipping link-local IP {ip_address} on {if_name}")
                continue
            
            full_if_name = if_name
            vlan = ip_config.get('vlan')
            if vlan:
                full_if_name = f"{if_name}.{vlan}"
            
            label_id = str(ip_config.get('label', ''))
            label_name = wan_labels.get(label_id, f"WAN-{label_id}" if label_id else "WAN")
            
            wan_interface = WANInterface(
                nepk=nepk,
                interface_name=full_if_name,
                label_name=label_name,
                ip_address=ip_address
            )
            
            interfaces.append(wan_interface)
            self.logger.info(f"   Found WAN interface: {wan_interface.display_name} - IP: {ip_address}")
        
        return interfaces
    
    def discover_wan_interfaces(self) -> List[WANInterface]:
        """Discover all WAN interfaces across all appliances"""
        self.logger.info("=" * 60)
        self.logger.info("DISCOVERING WAN INTERFACES")
        self.logger.info("=" * 60)
        
        self.appliances = self.get_all_appliances()
        if not self.appliances:
            self.logger.error("No appliances found!")
            return []
        
        all_wan_interfaces = []
        
        for nepk, appliance in self.appliances.items():
            self.logger.info(f"\nProcessing: {appliance.name} (NEPK: {nepk})")
            
            appliance.deployment = self.get_deployment_details(nepk)
            if not appliance.deployment:
                continue
            
            appliance.wan_interfaces = self.extract_wan_interfaces(appliance)
            all_wan_interfaces.extend(appliance.wan_interfaces)
        
        self._log_discovery_summary(all_wan_interfaces)
        return all_wan_interfaces
    
    def _log_discovery_summary(self, wan_interfaces: List[WANInterface]):
        """Log discovery summary"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("DISCOVERY SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Appliances: {len(self.appliances)}")
        self.logger.info(f"Total WAN Interfaces: {len(wan_interfaces)}")
        
        if wan_interfaces:
            self.logger.info("\nDiscovered WAN Interfaces:")
            for interface in wan_interfaces:
                appliance_name = self.appliances[interface.nepk].name
                self.logger.info(f"   {appliance_name}: {interface.display_name}")
    
    def get_interface_status(self, nepk: str, interface: str) -> Optional[Dict]:
        """Get operational status of a specific interface"""
        url = f"{self.base_url}/gms/rest/appliance/rest?nePk={nepk}&url=networkInterfaces"
        result = self._make_request('GET', url)
        
        if not result:
            return None
        
        interfaces = self._extract_interfaces_list(result)
        return self._find_interface_in_list(interfaces, interface)
    
    def _extract_interfaces_list(self, result: Union[Dict, List]) -> List[Dict]:
        """Extract interfaces list from API response"""
        if isinstance(result, list):
            return result
        
        if isinstance(result, dict):
            for key in ['interfaces', 'ifInfo']:
                if key in result and isinstance(result[key], list):
                    return result[key]
            
            if 'ifname' in result:
                return [result]
        
        return []
    
    def _find_interface_in_list(self, interfaces: List[Dict], target_interface: str) -> Optional[Dict]:
        """Find specific interface in interfaces list"""
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
                
            interface_names = [
                interface.get('ifname'),
                interface.get('name'),
                interface.get('interface')
            ]
            
            if target_interface in interface_names:
                return interface
        
        return None
    
    def set_interface_state(self, wan_interface: WANInterface, admin_up: bool) -> bool:
        """Enable or disable an interface"""
        appliance = self.appliances[wan_interface.nepk]
        state_str = "UP" if admin_up else "DOWN"
        
        self.logger.info(f"Setting {wan_interface.display_name} to {state_str} "
                        f"on {appliance.name}...")
        
        url = f"{self.base_url}/gms/rest/appliance/rest?nePk={wan_interface.nepk}&url=networkInterfaces"
        data = {
            "ifInfo": [{
                "ifname": wan_interface.interface_name,
                "admin": admin_up
            }]
        }
        
        result = self._make_request('POST', url, data)
        success = result is not None
        
        if success:
            self.logger.info(f"Successfully set {wan_interface.display_name} to {state_str}")
        else:
            self.logger.error(f"Failed to set {wan_interface.display_name} to {state_str}")
        
        return success
    
    def verify_interface_operational(self, wan_interface: WANInterface, max_wait: int = 60) -> bool:
        """Verify that an interface is operationally up with improved polling"""
        appliance = self.appliances[wan_interface.nepk]
        self.logger.info(f"Verifying {wan_interface.display_name} is operational on {appliance.name}...")
        
        start_time = time.time()
        check_interval = 5
        
        while time.time() - start_time < max_wait:
            status = self.get_interface_status(wan_interface.nepk, wan_interface.interface_name)
            
            if status:
                admin_status = status.get('admin', False)
                oper_status = status.get('oper', False)
                
                if admin_status and oper_status:
                    self.logger.info(f"Interface {wan_interface.display_name} is operational")
                    return True
                elif admin_status:
                    elapsed = int(time.time() - start_time)
                    self.logger.info(f"   Interface admin UP, waiting for operational... ({elapsed}s)")
                else:
                    self.logger.warning(f"   Interface not administratively up: {admin_status}")
            
            time.sleep(check_interval)
        
        self.logger.error(f"Interface {wan_interface.display_name} did not become operational "
                         f"after {max_wait} seconds")
        return False
    
    def run_single_interface_test(self, wan_interface: WANInterface) -> TestResult:
        """Run a single interface chaos test"""
        appliance = self.appliances[wan_interface.nepk]
        
        self.logger.info("\n" + "=" * 60)
        self.logger.info(f"CHAOS EVENT: {wan_interface.display_name} on {appliance.name}")
        self.logger.info(f"Chaos Duration: {self.failover_duration} seconds")
        self.logger.info("=" * 60)
        
        test_start_time = datetime.now()
        
        if not self._ensure_interface_initially_up(wan_interface):
            return TestResult(0, wan_interface, appliance.name, False, test_start_time)
        
        shutdown_time = datetime.now()
        if not self.set_interface_state(wan_interface, admin_up=False):
            return TestResult(0, wan_interface, appliance.name, False, test_start_time)
        
        self._wait_with_countdown(self.failover_duration)
        
        recovery_time = datetime.now()
        if not self.set_interface_state(wan_interface, admin_up=True):
            return TestResult(0, wan_interface, appliance.name, False, test_start_time)
        
        operational = self.verify_interface_operational(wan_interface)
        
        downtime = (recovery_time - shutdown_time).total_seconds()
        
        result = TestResult(
            cycle=0,
            wan_interface=wan_interface,
            appliance_name=appliance.name,
            success=operational,
            timestamp=test_start_time,
            downtime_seconds=downtime
        )
        
        self._log_test_summary(result)
        return result
    
    def _ensure_interface_initially_up(self, wan_interface: WANInterface) -> bool:
        """Ensure interface is initially up before testing"""
        self.logger.info("Checking initial interface status...")
        
        status = self.get_interface_status(wan_interface.nepk, wan_interface.interface_name)
        if not status:
            self.logger.error("Could not get interface status")
            return False
        
        admin_up = status.get('admin', False)
        oper_up = status.get('oper', False)
        
        self.logger.info(f"   Initial status - Admin: {admin_up}, Oper: {oper_up}")
        
        if not admin_up:
            self.logger.warning("Interface is administratively down, bringing it up...")
            if not self.set_interface_state(wan_interface, admin_up=True):
                return False
            time.sleep(10)
        
        return True
    
    def _wait_with_countdown(self, duration: int):
        """Wait with periodic countdown messages"""
        self.logger.info(f"Introducing chaos for {duration} seconds...")
        
        for remaining in range(duration, 0, -1):
            if remaining % 10 == 0 or remaining <= 5:
                self.logger.info(f"   {remaining} seconds of chaos remaining...")
            time.sleep(1)
    
    def _log_test_summary(self, result: TestResult):
        """Log individual chaos test summary"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("CHAOS TEST SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Status: {'PASSED' if result.success else 'FAILED'}")
        self.logger.info(f"Appliance: {result.appliance_name}")
        self.logger.info(f"Interface: {result.wan_interface.display_name}")
        self.logger.info(f"Chaos Duration: {result.downtime_seconds:.1f} seconds")
        self.logger.info(f"Recovery Status: {'Successful' if result.success else 'Failed'}")
        self.logger.info("=" * 60)
    
    def run_continuous_chaos_test(self, cycles: Optional[int] = None, 
                                    wait_between_cycles: int = 300):
        """Run continuous chaos tests with improved cycle management"""
        self.logger.info("STARTING SD-WAN CHAOS MONKEY")
        
        self.wan_interfaces = self.discover_wan_interfaces()
        if not self.wan_interfaces:
            self.logger.error("No WAN interfaces found! Aborting chaos test.")
            return
        
        self.logger.info(f"\nChaos Test Configuration:")
        self.logger.info(f"   WAN interfaces: {len(self.wan_interfaces)}")
        self.logger.info(f"   Wait between cycles: {wait_between_cycles} seconds")
        self.logger.info(f"   Total cycles: {'Infinite' if cycles is None else cycles}")
        
        results = []
        cycle_count = 0
        
        try:
            while cycles is None or cycle_count < cycles:
                cycle_count += 1
                
                wan_interface = self.wan_interfaces[self.current_test_index]
                appliance = self.appliances[wan_interface.nepk]
                
                self._log_cycle_header(cycle_count, wan_interface, appliance)
                
                result = self.run_single_interface_test(wan_interface)
                result.cycle = cycle_count
                results.append(result)
                
                self.current_test_index = (self.current_test_index + 1) % len(self.wan_interfaces)
                
                if cycles is None or cycle_count < cycles:
                    self._wait_between_cycles(wait_between_cycles)
        
        except KeyboardInterrupt:
            self.logger.info("\nChaos test interrupted by user")
        
        self._print_final_summary(results)
    
    def _log_cycle_header(self, cycle: int, wan_interface: WANInterface, appliance: ApplianceInfo):
        """Log cycle header information"""
        total_interfaces = len(self.wan_interfaces)
        current_position = self.current_test_index + 1
        
        self.logger.info("\n" + "#" * 60)
        self.logger.info(f"# CYCLE {cycle} - Interface {current_position} of {total_interfaces}")
        self.logger.info(f"# Target: {wan_interface.display_name} on {appliance.name}")
        self.logger.info("#" * 60)
    
    def _wait_between_cycles(self, wait_time: int):
        """Wait between test cycles with periodic updates"""
        self.logger.info(f"\nWaiting {wait_time} seconds before next cycle...")
        
        update_interval = min(30, wait_time // 4) if wait_time > 30 else wait_time
        
        for remaining in range(wait_time, 0, -update_interval):
            self.logger.info(f"   Next test in {remaining} seconds...")
            time.sleep(min(update_interval, remaining))
    
    def _print_final_summary(self, results: List[TestResult]):
        """Print comprehensive final chaos test summary"""
        if not results:
            self.logger.info("No chaos test results to summarize")
            return
        
        self.logger.info("\n" + "=" * 80)
        self.logger.info("SD-WAN CHAOS MONKEY - FINAL SUMMARY")
        self.logger.info("=" * 80)
        
        total_tests = len(results)
        successful_tests = sum(1 for r in results if r.success)
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        self.logger.info(f"Total Chaos Events: {total_tests}")
        self.logger.info(f"Successful Recoveries: {successful_tests}")
        self.logger.info(f"Failed Recoveries: {total_tests - successful_tests}")
        self.logger.info(f"Recovery Success Rate: {success_rate:.1f}%")
        
        self.logger.info("\nChaos Event Results:")
        for result in results:
            status = "PASS" if result.success else "FAIL"
            timestamp = result.timestamp.strftime('%H:%M:%S')
            self.logger.info(f"   Cycle {result.cycle:2d} [{timestamp}] {status} - "
                           f"{result.wan_interface.display_name} on {result.appliance_name} "
                           f"({result.downtime_seconds:.1f}s chaos duration)")
        
        self._log_per_appliance_summary(results)
        self._log_performance_metrics(results)
        
        self.logger.info("=" * 80)
    
    def _log_per_appliance_summary(self, results: List[TestResult]):
        """Log per-appliance test summary"""
        appliance_stats = {}
        
        for result in results:
            appliance = result.appliance_name
            if appliance not in appliance_stats:
                appliance_stats[appliance] = {'total': 0, 'success': 0, 'total_downtime': 0.0}
            
            stats = appliance_stats[appliance]
            stats['total'] += 1
            stats['total_downtime'] += result.downtime_seconds
            if result.success:
                stats['success'] += 1
        
        self.logger.info("\nPer-Appliance Resilience Results:")
        for appliance, stats in appliance_stats.items():
            rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            avg_downtime = stats['total_downtime'] / stats['total'] if stats['total'] > 0 else 0
            self.logger.info(f"   {appliance}: {stats['success']}/{stats['total']} "
                           f"({rate:.1f}% recovery rate) - Avg chaos duration: {avg_downtime:.1f}s")
    
    def _log_performance_metrics(self, results: List[TestResult]):
        """Log performance metrics from test results"""
        if not results:
            return
        
        successful_results = [r for r in results if r.success]
        
        if successful_results:
            downtimes = [r.downtime_seconds for r in successful_results]
            avg_downtime = sum(downtimes) / len(downtimes)
            min_downtime = min(downtimes)
            max_downtime = max(downtimes)
            
            self.logger.info("\nChaos Engineering Metrics:")
            self.logger.info(f"   Average chaos duration: {avg_downtime:.1f}s")
            self.logger.info(f"   Minimum chaos duration: {min_downtime:.1f}s")
            self.logger.info(f"   Maximum chaos duration: {max_downtime:.1f}s")


def setup_logging(debug: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SD-WAN Chaos Monkey - A chaos engineering tool for testing SD-WAN network resilience',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with API token (header auth)
  python3 sdwan_chaos_monkey.py --token YOUR_TOKEN --url https://orchestrator.example.com
  
  # Run with API token (query parameter auth)
  python3 sdwan_chaos_monkey.py --token YOUR_TOKEN --query-auth --url https://orchestrator.example.com
  
  # Run with basic authentication
  python3 sdwan_chaos_monkey.py --auth username:password --url https://orchestrator.example.com
  
  # Run single chaos test
  python3 sdwan_chaos_monkey.py --token YOUR_TOKEN --single-test 4.NE twan0
  
  # Run 10 cycles with 2-minute wait between cycles
  python3 sdwan_chaos_monkey.py --token YOUR_TOKEN --cycles 10 --wait 120
        """
    )
    
    # Authentication options
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        '--token', 
        help='API token for authentication (uses X-Auth-Token header by default)'
    )
    auth_group.add_argument(
        '--auth', 
        help='Username:password for basic auth'
    )
    
    # Required arguments
    parser.add_argument(
        '--url',
        default='https://jh-bgp-ha-sewan-orchsp-useast1.silverpeak.cloud',
        help='Orchestrator base URL (default: %(default)s)'
    )
    
    # Authentication method
    parser.add_argument(
        '--query-auth',
        action='store_true',
        help='Use apiKey query parameter instead of X-Auth-Token header for token auth'
    )
    
    # Test configuration
    parser.add_argument(
        '--duration',
        type=int,
        default=30,
        help='Interface chaos duration in seconds (default: %(default)s)',
        metavar='SECONDS'
    )
    
    # Continuous test options
    parser.add_argument(
        '--cycles',
        type=int,
        help='Number of chaos cycles (default: infinite)',
        metavar='N'
    )
    parser.add_argument(
        '--wait',
        type=int,
        default=300,
        help='Wait time between cycles in seconds (default: %(default)s = 5 minutes)',
        metavar='SECONDS'
    )
    
    # Single test mode
    parser.add_argument(
        '--single-test',
        nargs=2,
        metavar=('NEPK', 'INTERFACE'),
        help='Run a single chaos test on specific appliance and interface (e.g., --single-test 4.NE twan0)'
    )
    
    # Other options
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='HTTP request timeout in seconds (default: %(default)s)',
        metavar='SECONDS'
    )
    
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    """Validate and parse authentication arguments"""
    username = None
    password = None
    
    if args.auth:
        if ':' not in args.auth:
            raise ValueError("Auth format should be username:password")
        username, password = args.auth.split(':', 1)
    
    # Validate duration
    if args.duration <= 0:
        raise ValueError("Duration must be positive")
    
    # Validate wait time
    if args.wait < 0:
        raise ValueError("Wait time cannot be negative")
    
    # Validate cycles
    if args.cycles is not None and args.cycles <= 0:
        raise ValueError("Cycles must be positive")
    
    # Validate timeout
    if args.timeout <= 0:
        raise ValueError("Timeout must be positive")
    
    return username, password


def create_tester(args: argparse.Namespace, username: str, password: str) -> SDWANChaosMonkey:
    """Create and configure the SD-WAN Chaos Monkey"""
    return SDWANChaosMonkey(
        base_url=args.url,
        auth_token=args.token,
        username=username,
        password=password,
        failover_duration=args.duration,
        verify_ssl=not args.no_verify_ssl,
        use_query_auth=args.query_auth
    )


def run_single_test(tester: SDWANChaosMonkey, nepk: str, interface: str) -> int:
    """Run a single chaos test"""
    logger = logging.getLogger(__name__)
    
    # Discover appliances first
    tester.appliances = tester.get_all_appliances()
    if not tester.appliances:
        logger.error("No appliances discovered! Check your URL and authentication.")
        return 1
    
    if nepk not in tester.appliances:
        logger.error(f"Appliance {nepk} not found!")
        available = ', '.join(tester.appliances.keys())
        logger.error(f"Available appliances: {available}")
        return 1
    
    # Create WANInterface object for the chaos test
    wan_interface = WANInterface(
        nepk=nepk,
        interface_name=interface,
        label_name="Manual Chaos Test"
    )
    
    logger.info(f"Running single chaos test on {nepk}:{interface}")
    result = tester.run_single_interface_test(wan_interface)
    
    return 0 if result.success else 1


def run_continuous_test(tester: SDWANChaosMonkey, cycles: Optional[int], 
                       wait_between_cycles: int) -> int:
    """Run continuous chaos tests"""
    logger = logging.getLogger(__name__)
    
    logger.info("Starting SD-WAN chaos engineering tests...")
    tester.run_continuous_chaos_test(
        cycles=cycles,
        wait_between_cycles=wait_between_cycles
    )
    return 0


def main() -> int:
    """Main function with improved error handling and logging"""
    try:
        args = parse_arguments()
        setup_logging(args.debug)
        
        logger = logging.getLogger(__name__)
        
        # Validate arguments
        username, password = validate_arguments(args)
        
        # Create tester
        tester = create_tester(args, username, password)
        
        # Log startup information
        logger.info("SD-WAN Chaos Monkey Starting...")
        logger.info(f"Orchestrator URL: {args.url}")
        logger.info(f"Authentication: {'Token' if args.token else 'Basic Auth'}")
        logger.info(f"SSL Verification: {not args.no_verify_ssl}")
        logger.info(f"Chaos Duration: {args.duration} seconds")
        
        # Run appropriate test mode
        if args.single_test:
            nepk, interface = args.single_test
            return run_single_test(tester, nepk, interface)
        else:
            return run_continuous_test(tester, args.cycles, args.wait)
    
    except KeyboardInterrupt:
        logger = logging.getLogger(__name__)
        logger.info("\nChaos test interrupted by user")
        return 130
    
    except ValueError as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Invalid argument: {e}")
        return 2
    
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error: {e}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
