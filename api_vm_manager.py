"""
API-based VM resource manager using native Proxmox API calls.
Replaces SSH-based CLI commands with direct API communication.
"""
import logging
import time
import threading
from typing import Tuple, Optional, Dict, Any
from proxmox_api_client import ProxmoxAPIClient, ProxmoxAPIException


class APIVMResourceManager:
    """API-based VM resource manager with native Proxmox API integration."""
    
    def __init__(self, api_client: ProxmoxAPIClient, vm_id: int, config: dict):
        """
        Initialize API-based VM resource manager.
        
        Args:
            api_client: Authenticated Proxmox API client
            vm_id: VM ID to manage
            config: VM configuration dictionary
        """
        self.api_client = api_client
        self.vm_id = self._validate_vm_id(vm_id)
        self.config = config
        self.logger = logging.getLogger(f"api_vm_resource_manager.{vm_id}")
        self.last_scale_time = 0
        self.scale_cooldown = self.config.get("scale_cooldown", 300)
        self.scale_lock = threading.Lock()
        
        # Cache for VM node location
        self._vm_node: Optional[str] = None
        self._node_cache_time = 0
        self._node_cache_ttl = 300  # 5 minutes
    
    @staticmethod
    def _validate_vm_id(vm_id) -> int:
        """Validate VM ID to prevent injection."""
        try:
            vm_id_int = int(vm_id)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid VM ID format: {vm_id}")
        
        if not 100 <= vm_id_int <= 999999:
            raise ValueError(f"VM ID out of valid range: {vm_id_int}")
        
        return vm_id_int
    
    @staticmethod
    def _validate_resource_value(value, min_val: int, max_val: int, name: str) -> int:
        """Validate resource values to prevent injection and ensure bounds."""
        try:
            value_int = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid {name} value: {value}")
        
        if not min_val <= value_int <= max_val:
            raise ValueError(f"Invalid {name}: {value_int} (must be {min_val}-{max_val})")
        
        return value_int

    def _get_vm_node(self, force_refresh: bool = False) -> str:
        """
        Get the node hosting this VM with caching.
        
        Args:
            force_refresh: Force refresh of node cache
            
        Returns:
            Node name hosting the VM
        """
        current_time = time.time()
        
        # Return cached node if still valid
        if (not force_refresh and 
            self._vm_node and 
            (current_time - self._node_cache_time) < self._node_cache_ttl):
            return self._vm_node
        
        try:
            # Find VM node using API
            self._vm_node = self.api_client.find_vm_node(self.vm_id)
            self._node_cache_time = current_time
            self.logger.debug(f"VM {self.vm_id} located on node {self._vm_node}")
            return self._vm_node
        except Exception as e:
            self.logger.error(f"Failed to locate VM {self.vm_id}: {e}")
            raise

    def is_vm_running(self, retries: int = 3, delay: int = 2) -> bool:
        """
        Check if the VM is running using API calls.
        
        Args:
            retries: Number of retry attempts
            delay: Delay between retries in seconds
            
        Returns:
            True if VM is running, False otherwise
        """
        for attempt in range(1, retries + 1):
            try:
                node = self._get_vm_node()
                status_data = self.api_client.get_vm_status(self.vm_id, node)
                
                vm_status = status_data.get("status", "").lower()
                self.logger.debug(f"VM {self.vm_id} status: {vm_status}")
                
                if vm_status == "running":
                    self.logger.info(f"VM {self.vm_id} is running")
                    return True
                else:
                    self.logger.info(f"VM {self.vm_id} is not running (status: {vm_status})")
                    return False
                    
            except Exception as e:
                self.logger.warning(
                    f"Attempt {attempt}/{retries} failed to check VM status: {e}"
                )
                if attempt < retries:
                    time.sleep(delay * attempt)  # Progressive backoff
                else:
                    self.logger.error(
                        f"Unable to determine status of VM {self.vm_id} after {retries} attempts"
                    )
                    return False
        
        return False

    def get_resource_usage(self) -> Tuple[float, float]:
        """
        Retrieve CPU and RAM usage as percentages using API calls.
        
        Returns:
            Tuple of (cpu_usage_percent, ram_usage_percent)
        """
        try:
            if not self.is_vm_running():
                return 0.0, 0.0
            
            node = self._get_vm_node()
            
            # Get VM status for current resource usage
            status_data = self.api_client.get_vm_status(self.vm_id, node)
            
            # Parse CPU usage
            cpu_usage = self._parse_cpu_usage_from_status(status_data)
            
            # Parse RAM usage  
            ram_usage = self._parse_ram_usage_from_status(status_data)
            
            self.logger.debug(
                f"VM {self.vm_id} resource usage - CPU: {cpu_usage:.1f}%, RAM: {ram_usage:.1f}%"
            )
            
            return cpu_usage, ram_usage
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve resource usage for VM {self.vm_id}: {e}")
            return 0.0, 0.0

    def _parse_cpu_usage_from_status(self, status_data: Dict[str, Any]) -> float:
        """
        Parse CPU usage from VM status data.
        
        Args:
            status_data: VM status data from API
            
        Returns:
            CPU usage percentage
        """
        try:
            # CPU usage is typically reported as a fraction (0.0 to 1.0+)
            cpu_value = status_data.get("cpu", 0)
            
            if isinstance(cpu_value, (int, float)):
                # Convert to percentage and cap at 100%
                cpu_percentage = min(cpu_value * 100, 100.0)
                
                # Validate reasonable range
                if 0 <= cpu_percentage <= 100:
                    return cpu_percentage
                else:
                    self.logger.warning(f"CPU usage out of range: {cpu_percentage}%")
                    return 0.0
            else:
                self.logger.warning(f"Invalid CPU usage format: {cpu_value}")
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error parsing CPU usage: {e}")
            return 0.0

    def _parse_ram_usage_from_status(self, status_data: Dict[str, Any]) -> float:
        """
        Parse RAM usage from VM status data.
        
        Args:
            status_data: VM status data from API
            
        Returns:
            RAM usage percentage
        """
        try:
            # Memory values are typically in bytes
            mem_used = status_data.get("mem", 0)
            mem_max = status_data.get("maxmem", 1)  # Avoid division by zero
            
            if isinstance(mem_used, (int, float)) and isinstance(mem_max, (int, float)):
                if mem_max > 0:
                    ram_percentage = (mem_used / mem_max) * 100
                    
                    # Validate reasonable range
                    if 0 <= ram_percentage <= 100:
                        return ram_percentage
                    else:
                        self.logger.warning(f"RAM usage out of range: {ram_percentage}%")
                        return 0.0
                else:
                    self.logger.warning("Maximum memory is zero")
                    return 0.0
            else:
                self.logger.warning(f"Invalid memory values: used={mem_used}, max={mem_max}")
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error parsing RAM usage: {e}")
            return 0.0

    def can_scale(self) -> bool:
        """
        Determine if scaling can occur using a lock to avoid race conditions.
        
        Returns:
            True if scaling is allowed, False if in cooldown
        """
        with self.scale_lock:
            current_time = time.time()
            if current_time - self.last_scale_time < self.scale_cooldown:
                return False
            self.last_scale_time = current_time
            return True

    def scale_cpu(self, direction: str) -> bool:
        """
        Scale the CPU cores of the VM using API calls.
        
        Args:
            direction: Scaling direction ('up' or 'down')
            
        Returns:
            True if scaling occurred, False otherwise
        """
        if direction not in ['up', 'down']:
            raise ValueError(f"Invalid scaling direction: {direction}")
        
        if not self.can_scale():
            self.logger.debug(f"CPU scaling for VM {self.vm_id} is in cooldown")
            return False

        try:
            node = self._get_vm_node()
            
            # Get current configuration
            config_data = self.api_client.get_vm_config(self.vm_id, node)
            
            current_cores = int(config_data.get("cores", 1))
            current_sockets = int(config_data.get("sockets", 1))
            
            max_cores = self._get_max_cores()
            min_cores = self._get_min_cores()
            
            self.logger.debug(
                f"VM {self.vm_id} current CPU config: {current_cores} cores, "
                f"limits: {min_cores}-{max_cores}"
            )

            new_cores = current_cores
            if direction == "up" and current_cores < max_cores:
                new_cores = current_cores + 1
            elif direction == "down" and current_cores > min_cores:
                new_cores = current_cores - 1
            else:
                self.logger.info(f"No CPU scaling required for VM {self.vm_id}")
                return False

            # Update VM configuration
            config_updates = {"cores": new_cores}
            
            # Also update vcpus to match cores for hotplug support
            config_updates["vcpus"] = new_cores * current_sockets
            
            self.api_client.update_vm_config(self.vm_id, config_updates, node)
            
            self.logger.info(
                f"Scaled CPU for VM {self.vm_id} from {current_cores} to {new_cores} cores"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to scale CPU for VM {self.vm_id}: {e}")
            raise

    def scale_ram(self, direction: str) -> bool:
        """
        Scale the RAM of the VM using API calls.
        
        Args:
            direction: Scaling direction ('up' or 'down')
            
        Returns:
            True if scaling occurred, False otherwise
        """
        if direction not in ['up', 'down']:
            raise ValueError(f"Invalid scaling direction: {direction}")
        
        if not self.can_scale():
            self.logger.debug(f"RAM scaling for VM {self.vm_id} is in cooldown")
            return False

        try:
            node = self._get_vm_node()
            
            # Get current configuration
            config_data = self.api_client.get_vm_config(self.vm_id, node)
            
            current_ram = int(config_data.get("memory", 512))  # RAM in MB
            max_ram = self._get_max_ram()
            min_ram = self._get_min_ram()
            
            self.logger.debug(
                f"VM {self.vm_id} current RAM: {current_ram}MB, limits: {min_ram}-{max_ram}MB"
            )

            new_ram = current_ram
            if direction == "up" and current_ram < max_ram:
                new_ram = min(current_ram + 512, max_ram)  # Increase by 512MB
            elif direction == "down" and current_ram > min_ram:
                new_ram = max(current_ram - 512, min_ram)  # Decrease by 512MB
            else:
                self.logger.info(f"No RAM scaling required for VM {self.vm_id}")
                return False

            # Update VM configuration
            config_updates = {"memory": new_ram}
            self.api_client.update_vm_config(self.vm_id, config_updates, node)
            
            self.logger.info(
                f"Scaled RAM for VM {self.vm_id} from {current_ram}MB to {new_ram}MB"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to scale RAM for VM {self.vm_id}: {e}")
            raise

    def _get_max_cores(self) -> int:
        """Retrieve maximum allowed CPU cores."""
        return self.config.get("max_cores", 8)

    def _get_min_cores(self) -> int:
        """Retrieve minimum allowed CPU cores."""
        return self.config.get("min_cores", 1)

    def _get_max_ram(self) -> int:
        """Retrieve maximum allowed RAM in MB."""
        return self.config.get("max_ram", 16384)

    def _get_min_ram(self) -> int:
        """Retrieve minimum allowed RAM in MB."""
        return self.config.get("min_ram", 512)

    def get_vm_info(self) -> Dict[str, Any]:
        """
        Get comprehensive VM information including current configuration and status.
        
        Returns:
            Dictionary containing VM information
        """
        try:
            node = self._get_vm_node()
            
            # Get both status and configuration
            status_data = self.api_client.get_vm_status(self.vm_id, node)
            config_data = self.api_client.get_vm_config(self.vm_id, node)
            
            vm_info = {
                "vm_id": self.vm_id,
                "node": node,
                "status": status_data.get("status", "unknown"),
                "cores": int(config_data.get("cores", 1)),
                "memory_mb": int(config_data.get("memory", 512)),
                "cpu_usage_percent": self._parse_cpu_usage_from_status(status_data),
                "ram_usage_percent": self._parse_ram_usage_from_status(status_data),
                "uptime": status_data.get("uptime", 0),
                "pid": status_data.get("pid"),
                "name": config_data.get("name", f"VM-{self.vm_id}")
            }
            
            return vm_info
            
        except Exception as e:
            self.logger.error(f"Failed to get VM info for {self.vm_id}: {e}")
            raise ProxmoxAPIException(f"Failed to get VM info: {e}")

    def wait_for_task_completion(self, task_id: str, node: str, timeout: int = 300) -> bool:
        """
        Wait for a Proxmox task to complete.
        
        Args:
            task_id: Task ID to monitor
            node: Node where task is running
            timeout: Maximum wait time in seconds
            
        Returns:
            True if task completed successfully, False otherwise
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Get task status
                task_status = self.api_client._make_request(
                    "GET", f"/nodes/{node}/tasks/{task_id}/status"
                )
                
                status = task_status.get("data", {}).get("status")
                
                if status == "OK":
                    self.logger.debug(f"Task {task_id} completed successfully")
                    return True
                elif status in ["stopped", "error"]:
                    self.logger.error(f"Task {task_id} failed with status: {status}")
                    return False
                    
                # Task still running, wait a bit
                time.sleep(2)
                
            except Exception as e:
                self.logger.warning(f"Error checking task {task_id} status: {e}")
                time.sleep(2)
        
        self.logger.error(f"Task {task_id} did not complete within {timeout} seconds")
        return False