"""
Proxmox VE API client for secure VM autoscaling.
Replaces SSH-based communication with native Proxmox API calls.
"""
import logging
import time
import urllib3
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class ProxmoxAPIException(Exception):
    """Custom exception for Proxmox API-related errors."""
    pass


class ProxmoxAuthenticationError(ProxmoxAPIException):
    """Authentication-specific exception."""
    pass


class ProxmoxAPIClient:
    """
    Secure Proxmox VE API client with enhanced features:
    - Support for both API tokens and username/password authentication
    - Automatic node discovery for clusters
    - Configurable SSL certificate validation
    - Connection retry logic with exponential backoff
    - Comprehensive error handling and logging
    """

    def __init__(
        self,
        host: str,
        port: int = 8006,
        # Authentication options
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_token_id: Optional[str] = None,
        api_token_secret: Optional[str] = None,
        # SSL options
        verify_ssl: bool = True,
        ca_cert_path: Optional[str] = None,
        # Connection options
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        # Node options
        node_name: Optional[str] = None,
        auto_discover_nodes: bool = False
    ):
        """
        Initialize Proxmox API client.
        
        Args:
            host: Proxmox VE host address
            port: API port (default 8006)
            username: Username for username/password auth
            password: Password for username/password auth
            api_token_id: API token ID for token-based auth
            api_token_secret: API token secret for token-based auth
            verify_ssl: Whether to verify SSL certificates
            ca_cert_path: Path to custom CA certificate file
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retries
            node_name: Specific node name (for single node setups)
            auto_discover_nodes: Whether to auto-discover cluster nodes
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.api_token_id = api_token_id
        self.api_token_secret = api_token_secret
        self.verify_ssl = verify_ssl
        self.ca_cert_path = ca_cert_path
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.node_name = node_name
        self.auto_discover_nodes = auto_discover_nodes
        
        # Initialize logging
        self.logger = logging.getLogger(f"proxmox_api_client.{host}")
        
        # Validate initialization parameters
        self._validate_init_params()
        
        # Set up base URL
        self.base_url = f"https://{host}:{port}/api2/json"
        
        # Initialize session
        self.session = self._create_session()
        
        # Authentication state
        self._auth_ticket = None
        self._csrf_token = None
        self._authenticated = False
        
        # Node discovery cache
        self._discovered_nodes: List[str] = []
        self._node_discovery_time = 0
        self._node_cache_ttl = 300  # 5 minutes

    def _validate_init_params(self) -> None:
        """Validate initialization parameters."""
        # Check authentication parameters
        has_password_auth = self.username and self.password
        has_token_auth = self.api_token_id and self.api_token_secret
        
        if not has_password_auth and not has_token_auth:
            raise ValueError(
                "Either username/password or api_token_id/api_token_secret must be provided"
            )
        
        # Validate SSL certificate path if provided
        if self.ca_cert_path and not Path(self.ca_cert_path).exists():
            raise FileNotFoundError(f"CA certificate file not found: {self.ca_cert_path}")
        
        # Validate port
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid port number: {self.port}")
        
        # Validate timeout
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive: {self.timeout}")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic and SSL configuration."""
        session = requests.Session()
        
        # Configure SSL verification
        if not self.verify_ssl:
            session.verify = False
            # Disable SSL warnings for self-signed certificates
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning("SSL certificate verification is disabled")
        elif self.ca_cert_path:
            session.verify = self.ca_cert_path
            self.logger.info(f"Using custom CA certificate: {self.ca_cert_path}")
        else:
            session.verify = True
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # Set default timeout
        session.timeout = self.timeout
        
        return session

    def authenticate(self) -> None:
        """Authenticate with Proxmox API using available credentials."""
        if self._authenticated:
            self.logger.debug("Already authenticated")
            return
        
        try:
            if self.api_token_id and self.api_token_secret:
                self._authenticate_with_token()
            elif self.username and self.password:
                self._authenticate_with_password()
            else:
                raise ProxmoxAuthenticationError("No valid authentication method available")
            
            self._authenticated = True
            self.logger.info(f"Successfully authenticated to Proxmox VE at {self.host}:{self.port}")
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            raise ProxmoxAuthenticationError(f"Authentication failed: {e}")

    def _authenticate_with_token(self) -> None:
        """Authenticate using API token."""
        self.logger.debug("Authenticating with API token")
        
        # For API tokens, we set the authorization header
        auth_header = f"PVEAPIToken={self.api_token_id}={self.api_token_secret}"
        self.session.headers.update({"Authorization": auth_header})
        
        # Test authentication by making a simple API call
        try:
            response = self._make_request("GET", "/version")
            if response.get("data"):
                self.logger.debug("API token authentication successful")
            else:
                raise ProxmoxAuthenticationError("API token authentication failed")
        except Exception as e:
            raise ProxmoxAuthenticationError(f"API token validation failed: {e}")

    def _authenticate_with_password(self) -> None:
        """Authenticate using username/password to get ticket."""
        self.logger.debug("Authenticating with username/password")
        
        auth_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            # Get authentication ticket
            response = self.session.post(
                urljoin(self.base_url, "/access/ticket"),
                data=auth_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            auth_result = response.json()
            if "data" not in auth_result:
                raise ProxmoxAuthenticationError("Invalid authentication response")
            
            data = auth_result["data"]
            self._auth_ticket = data.get("ticket")
            self._csrf_token = data.get("CSRFPreventionToken")
            
            if not self._auth_ticket:
                raise ProxmoxAuthenticationError("No authentication ticket received")
            
            # Set session cookies and headers
            self.session.cookies.set("PVEAuthCookie", self._auth_ticket)
            if self._csrf_token:
                self.session.headers.update({"CSRFPreventionToken": self._csrf_token})
            
            self.logger.debug("Username/password authentication successful")
            
        except requests.exceptions.RequestException as e:
            raise ProxmoxAuthenticationError(f"Authentication request failed: {e}")
        except KeyError as e:
            raise ProxmoxAuthenticationError(f"Invalid authentication response format: {e}")

    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make authenticated API request.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to base URL)
            params: Query parameters
            data: Request body data
            **kwargs: Additional request parameters
            
        Returns:
            Dict containing API response data
            
        Raises:
            ProxmoxAPIException: If request fails
        """
        if not self._authenticated:
            self.authenticate()
        
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        try:
            self.logger.debug(f"Making {method} request to {endpoint}")
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                **kwargs
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Check for Proxmox API errors
            if "errors" in result:
                error_msg = "; ".join(result["errors"])
                raise ProxmoxAPIException(f"Proxmox API error: {error_msg}")
            
            return result
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                # Authentication expired, try to re-authenticate once
                self._authenticated = False
                self.authenticate()
                return self._make_request(method, endpoint, params, data, **kwargs)
            else:
                raise ProxmoxAPIException(f"HTTP error {e.response.status_code}: {e}")
        except requests.exceptions.RequestException as e:
            raise ProxmoxAPIException(f"Request failed: {e}")
        except ValueError as e:
            raise ProxmoxAPIException(f"Invalid JSON response: {e}")

    def discover_nodes(self, force_refresh: bool = False) -> List[str]:
        """
        Discover available nodes in the cluster.
        
        Args:
            force_refresh: Force refresh of node cache
            
        Returns:
            List of node names
        """
        current_time = time.time()
        
        # Return cached nodes if still valid
        if (not force_refresh and 
            self._discovered_nodes and 
            (current_time - self._node_discovery_time) < self._node_cache_ttl):
            return self._discovered_nodes
        
        try:
            self.logger.debug("Discovering cluster nodes")
            
            # Use cluster resources endpoint to find nodes
            response = self._make_request("GET", "/cluster/resources", params={"type": "node"})
            
            nodes = []
            for resource in response.get("data", []):
                if resource.get("type") == "node" and resource.get("node"):
                    node_name = resource["node"]
                    # Only include online nodes
                    if resource.get("status") == "online":
                        nodes.append(node_name)
                        self.logger.debug(f"Discovered online node: {node_name}")
                    else:
                        self.logger.warning(f"Node {node_name} is offline")
            
            if not nodes:
                # Fallback: if no nodes discovered and we have a specific node name, use it
                if self.node_name:
                    nodes = [self.node_name]
                    self.logger.info(f"Using configured node: {self.node_name}")
                else:
                    raise ProxmoxAPIException("No online nodes discovered and no node_name configured")
            
            self._discovered_nodes = nodes
            self._node_discovery_time = current_time
            
            self.logger.info(f"Discovered {len(nodes)} online nodes: {', '.join(nodes)}")
            return nodes
            
        except Exception as e:
            # Fallback to configured node if discovery fails
            if self.node_name:
                self.logger.warning(f"Node discovery failed, using configured node {self.node_name}: {e}")
                return [self.node_name]
            else:
                self.logger.error(f"Node discovery failed and no fallback node configured: {e}")
                raise ProxmoxAPIException(f"Node discovery failed: {e}")

    def get_primary_node(self) -> str:
        """
        Get the primary node to use for operations.
        
        Returns:
            Primary node name
        """
        if self.node_name:
            # Use explicitly configured node
            return self.node_name
        elif self.auto_discover_nodes:
            # Use first discovered node
            nodes = self.discover_nodes()
            return nodes[0] if nodes else None
        else:
            raise ProxmoxAPIException("No node specified and auto-discovery disabled")

    def find_vm_node(self, vm_id: int) -> str:
        """
        Find which node hosts a specific VM.
        
        Args:
            vm_id: VM ID to search for
            
        Returns:
            Node name hosting the VM
            
        Raises:
            ProxmoxAPIException: If VM not found
        """
        try:
            self.logger.debug(f"Finding node for VM {vm_id}")
            
            # Get all cluster resources
            response = self._make_request("GET", "/cluster/resources")
            
            for resource in response.get("data", []):
                if (resource.get("type") == "qemu" and 
                    resource.get("vmid") == vm_id):
                    node = resource.get("node")
                    if node:
                        self.logger.debug(f"VM {vm_id} found on node {node}")
                        return node
            
            raise ProxmoxAPIException(f"VM {vm_id} not found in cluster")
            
        except Exception as e:
            if "not found" in str(e):
                raise
            else:
                raise ProxmoxAPIException(f"Failed to find VM {vm_id}: {e}")

    def get_vm_status(self, vm_id: int, node: Optional[str] = None) -> Dict[str, Any]:
        """
        Get VM status information.
        
        Args:
            vm_id: VM ID
            node: Node name (auto-detected if not provided)
            
        Returns:
            Dict containing VM status information
        """
        if not node:
            node = self.find_vm_node(vm_id)
        
        endpoint = f"/nodes/{node}/qemu/{vm_id}/status/current"
        response = self._make_request("GET", endpoint)
        return response.get("data", {})

    def get_vm_config(self, vm_id: int, node: Optional[str] = None) -> Dict[str, Any]:
        """
        Get VM configuration.
        
        Args:
            vm_id: VM ID
            node: Node name (auto-detected if not provided)
            
        Returns:
            Dict containing VM configuration
        """
        if not node:
            node = self.find_vm_node(vm_id)
        
        endpoint = f"/nodes/{node}/qemu/{vm_id}/config"
        response = self._make_request("GET", endpoint)
        return response.get("data", {})

    def update_vm_config(
        self, 
        vm_id: int, 
        config_updates: Dict[str, Any], 
        node: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update VM configuration.
        
        Args:
            vm_id: VM ID
            config_updates: Configuration parameters to update
            node: Node name (auto-detected if not provided)
            
        Returns:
            Dict containing operation result
        """
        if not node:
            node = self.find_vm_node(vm_id)
        
        endpoint = f"/nodes/{node}/qemu/{vm_id}/config"
        response = self._make_request("PUT", endpoint, data=config_updates)
        return response.get("data", {})

    def get_node_status(self, node: Optional[str] = None) -> Dict[str, Any]:
        """
        Get node status information.
        
        Args:
            node: Node name (uses primary node if not provided)
            
        Returns:
            Dict containing node status information
        """
        if not node:
            node = self.get_primary_node()
        
        endpoint = f"/nodes/{node}/status"
        response = self._make_request("GET", endpoint)
        return response.get("data", {})

    def get_cluster_resources(self, resource_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get cluster resources information.
        
        Args:
            resource_type: Filter by resource type (vm, node, storage, etc.)
            
        Returns:
            List of resource information dictionaries
        """
        params = {}
        if resource_type:
            params["type"] = resource_type
        
        response = self._make_request("GET", "/cluster/resources", params=params)
        return response.get("data", [])

    def close(self) -> None:
        """Close the API client session."""
        if self.session:
            try:
                self.session.close()
                self.logger.debug(f"API session closed for {self.host}")
            except Exception as e:
                self.logger.error(f"Error closing API session: {e}")
            finally:
                self.session = None
                self._authenticated = False

    def __enter__(self):
        """Context manager entry."""
        self.authenticate()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager exit."""
        self.close()

    def __del__(self):
        """Destructor to ensure session cleanup."""
        self.close()