"""
API-based host resource checker using native Proxmox API calls.
Replaces SSH-based CLI commands with direct API communication.
"""
import logging
from typing import Dict, Any, Optional
from proxmox_api_client import ProxmoxAPIClient, ProxmoxAPIException


class APIHostResourceChecker:
    """
    API-based host resource checker with native Proxmox API integration.
    """

    def __init__(self, api_client: ProxmoxAPIClient, node_name: Optional[str] = None):
        """
        Initialize the API-based HostResourceChecker.
        
        Args:
            api_client: Authenticated Proxmox API client
            node_name: Specific node to check (uses primary node if not provided)
        """
        self.api_client = api_client
        self.node_name = node_name
        self.logger = logging.getLogger("api_host_resource_checker")

    def check_host_resources(self, max_host_cpu_percent: float, max_host_ram_percent: float) -> bool:
        """
        Check host CPU and RAM usage against specified thresholds using API calls.
        
        Args:
            max_host_cpu_percent: Maximum allowable CPU usage percentage
            max_host_ram_percent: Maximum allowable RAM usage percentage
            
        Returns:
            True if resources are within limits, False otherwise
        """
        # Validate input parameters
        if not (0 <= max_host_cpu_percent <= 100):
            raise ValueError(f"Invalid max_host_cpu_percent: {max_host_cpu_percent}")
        if not (0 <= max_host_ram_percent <= 100):
            raise ValueError(f"Invalid max_host_ram_percent: {max_host_ram_percent}")
        
        try:
            # Get node name to check
            node = self.node_name or self.api_client.get_primary_node()
            
            self.logger.debug(f"Checking resource usage for node: {node}")
            
            # Get node status from API
            node_status = self.api_client.get_node_status(node)
            
            # Parse CPU and RAM usage
            host_cpu_usage = self._parse_cpu_usage(node_status)
            host_ram_usage = self._parse_ram_usage(node_status)
            
            # Log current resource usage
            self.logger.info(
                f"Node {node} resource usage - CPU: {host_cpu_usage:.2f}%, RAM: {host_ram_usage:.2f}%"
            )
            
            # Check CPU usage threshold
            if host_cpu_usage > max_host_cpu_percent:
                self.logger.warning(
                    f"Node {node} CPU usage exceeds maximum allowed limit: "
                    f"{host_cpu_usage:.2f}% > {max_host_cpu_percent}%"
                )
                return False
                
            # Check RAM usage threshold
            if host_ram_usage > max_host_ram_percent:
                self.logger.warning(
                    f"Node {node} RAM usage exceeds maximum allowed limit: "
                    f"{host_ram_usage:.2f}% > {max_host_ram_percent}%"
                )
                return False
                
            # Resources are within limits
            self.logger.debug(f"Node {node} resources are within acceptable limits")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to check host resources: {e}")
            raise ProxmoxAPIException(f"Host resource check failed: {e}")

    def _parse_cpu_usage(self, node_status: Dict[str, Any]) -> float:
        """
        Parse CPU usage from node status data.
        
        Args:
            node_status: Node status data from API
            
        Returns:
            CPU usage percentage
        """
        try:
            # CPU usage is typically reported as a fraction (0.0 to number_of_cores)
            cpu_value = node_status.get("cpu", 0)
            
            if isinstance(cpu_value, (int, float)):
                # Convert to percentage (CPU value is already normalized to 0.0-1.0+)
                cpu_percentage = cpu_value * 100
                
                # Cap at 100% to handle multi-core scenarios
                cpu_percentage = min(cpu_percentage, 100.0)
                
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

    def _parse_ram_usage(self, node_status: Dict[str, Any]) -> float:
        """
        Parse RAM usage from node status data.
        
        Args:
            node_status: Node status data from API
            
        Returns:
            RAM usage percentage
        """
        try:
            # Memory data is typically nested in a memory object
            memory_data = node_status.get("memory", {})
            
            if isinstance(memory_data, dict):
                total_mem = memory_data.get("total", 1)  # Avoid division by zero
                used_mem = memory_data.get("used", 0)
                free_mem = memory_data.get("free", 0)
                
                # Validate memory values
                for mem_val, name in [(total_mem, 'total'), (used_mem, 'used'), (free_mem, 'free')]:
                    if not isinstance(mem_val, (int, float)) or mem_val < 0:
                        self.logger.warning(f"Invalid {name} memory value: {mem_val}")
                        return 0.0
                
                if total_mem <= 0:
                    self.logger.warning("Total memory is zero or negative")
                    return 0.0
                
                # Calculate RAM usage percentage
                # Note: Some Proxmox versions may include buffer/cache in 'used'
                ram_percentage = (used_mem / total_mem) * 100
                
                # Validate calculated percentage
                if 0 <= ram_percentage <= 100:
                    return ram_percentage
                else:
                    self.logger.warning(f"Calculated RAM usage out of range: {ram_percentage}%")
                    return 0.0
                    
            else:
                # Handle case where memory is a direct value (older API versions)
                if isinstance(memory_data, (int, float)):
                    # Assume it's a percentage if it's between 0 and 1
                    if 0 <= memory_data <= 1:
                        return memory_data * 100
                    # Otherwise assume it's already a percentage
                    elif 0 <= memory_data <= 100:
                        return memory_data
                
                self.logger.warning(f"Invalid memory data format: {memory_data}")
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error parsing RAM usage: {e}")
            return 0.0

    def get_detailed_host_info(self, node: Optional[str] = None) -> Dict[str, Any]:
        """
        Get detailed host information including resource usage and system details.
        
        Args:
            node: Node name (uses configured or primary node if not provided)
            
        Returns:
            Dictionary containing detailed host information
        """
        try:
            target_node = node or self.node_name or self.api_client.get_primary_node()
            
            # Get comprehensive node status
            node_status = self.api_client.get_node_status(target_node)
            
            # Parse resource information
            cpu_usage = self._parse_cpu_usage(node_status)
            ram_usage = self._parse_ram_usage(node_status)
            
            # Extract additional system information
            memory_data = node_status.get("memory", {})
            
            host_info = {
                "node_name": target_node,
                "cpu_usage_percent": cpu_usage,
                "ram_usage_percent": ram_usage,
                "uptime": node_status.get("uptime", 0),
                "load_average": node_status.get("loadavg", []),
                "memory": {
                    "total_bytes": memory_data.get("total", 0),
                    "used_bytes": memory_data.get("used", 0),
                    "free_bytes": memory_data.get("free", 0),
                    "total_gb": round(memory_data.get("total", 0) / (1024**3), 2),
                    "used_gb": round(memory_data.get("used", 0) / (1024**3), 2),
                    "free_gb": round(memory_data.get("free", 0) / (1024**3), 2)
                },
                "swap": {
                    "total_bytes": node_status.get("swap", {}).get("total", 0),
                    "used_bytes": node_status.get("swap", {}).get("used", 0),
                    "free_bytes": node_status.get("swap", {}).get("free", 0)
                },
                "kernel_version": node_status.get("kversion", "unknown"),
                "pve_version": node_status.get("pveversion", "unknown"),
                "cpu_info": {
                    "cpu_count": node_status.get("cpuinfo", {}).get("cpus", 0),
                    "cpu_model": node_status.get("cpuinfo", {}).get("model", "unknown"),
                    "cpu_sockets": node_status.get("cpuinfo", {}).get("sockets", 0),
                }
            }
            
            return host_info
            
        except Exception as e:
            self.logger.error(f"Failed to get detailed host info for node {target_node}: {e}")
            raise ProxmoxAPIException(f"Failed to get host info: {e}")

    def check_multiple_nodes(
        self, 
        max_cpu_percent: float, 
        max_ram_percent: float,
        nodes: Optional[list] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Check resource usage across multiple nodes.
        
        Args:
            max_cpu_percent: Maximum allowable CPU usage percentage
            max_ram_percent: Maximum allowable RAM usage percentage
            nodes: List of nodes to check (auto-discovers if not provided)
            
        Returns:
            Dictionary mapping node names to their resource check results
        """
        try:
            # Get nodes to check
            if nodes is None:
                nodes = self.api_client.discover_nodes()
            
            results = {}
            
            for node in nodes:
                try:
                    self.logger.debug(f"Checking resources for node: {node}")
                    
                    # Get node status
                    node_status = self.api_client.get_node_status(node)
                    
                    # Parse resource usage
                    cpu_usage = self._parse_cpu_usage(node_status)
                    ram_usage = self._parse_ram_usage(node_status)
                    
                    # Check if within limits
                    cpu_ok = cpu_usage <= max_cpu_percent
                    ram_ok = ram_usage <= max_ram_percent
                    overall_ok = cpu_ok and ram_ok
                    
                    results[node] = {
                        "cpu_usage_percent": cpu_usage,
                        "ram_usage_percent": ram_usage,
                        "cpu_within_limit": cpu_ok,
                        "ram_within_limit": ram_ok,
                        "overall_within_limits": overall_ok,
                        "max_cpu_percent": max_cpu_percent,
                        "max_ram_percent": max_ram_percent,
                        "status": "OK" if overall_ok else "OVER_LIMIT"
                    }
                    
                    if not overall_ok:
                        self.logger.warning(
                            f"Node {node} resources exceed limits - "
                            f"CPU: {cpu_usage:.1f}%/{max_cpu_percent}%, "
                            f"RAM: {ram_usage:.1f}%/{max_ram_percent}%"
                        )
                    else:
                        self.logger.debug(
                            f"Node {node} resources OK - "
                            f"CPU: {cpu_usage:.1f}%, RAM: {ram_usage:.1f}%"
                        )
                        
                except Exception as e:
                    self.logger.error(f"Failed to check resources for node {node}: {e}")
                    results[node] = {
                        "status": "ERROR",
                        "error": str(e),
                        "overall_within_limits": False
                    }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to check multiple nodes: {e}")
            raise ProxmoxAPIException(f"Multi-node resource check failed: {e}")

    def get_cluster_resource_summary(self) -> Dict[str, Any]:
        """
        Get a summary of cluster-wide resource usage.
        
        Returns:
            Dictionary containing cluster resource summary
        """
        try:
            # Get cluster resources
            cluster_resources = self.api_client.get_cluster_resources()
            
            # Initialize counters
            total_nodes = 0
            online_nodes = 0
            total_vms = 0
            running_vms = 0
            total_cpu_cores = 0
            total_memory_gb = 0
            
            node_resources = {}
            
            for resource in cluster_resources:
                resource_type = resource.get("type", "")
                
                if resource_type == "node":
                    total_nodes += 1
                    if resource.get("status") == "online":
                        online_nodes += 1
                        
                        node_name = resource.get("node", "unknown")
                        node_resources[node_name] = {
                            "cpu_cores": resource.get("maxcpu", 0),
                            "memory_gb": round(resource.get("maxmem", 0) / (1024**3), 2),
                            "cpu_usage_percent": (resource.get("cpu", 0) * 100),
                            "memory_usage_percent": (
                                (resource.get("mem", 0) / resource.get("maxmem", 1)) * 100
                                if resource.get("maxmem", 0) > 0 else 0
                            ),
                            "status": resource.get("status", "unknown")
                        }
                        
                        total_cpu_cores += resource.get("maxcpu", 0)
                        total_memory_gb += resource.get("maxmem", 0) / (1024**3)
                        
                elif resource_type in ["qemu", "lxc"]:
                    total_vms += 1
                    if resource.get("status") == "running":
                        running_vms += 1
            
            summary = {
                "cluster_summary": {
                    "total_nodes": total_nodes,
                    "online_nodes": online_nodes,
                    "total_vms": total_vms,
                    "running_vms": running_vms,
                    "total_cpu_cores": total_cpu_cores,
                    "total_memory_gb": round(total_memory_gb, 2)
                },
                "node_details": node_resources,
                "timestamp": int(time.time() if 'time' in globals() else 0)
            }
            
            self.logger.info(
                f"Cluster summary: {online_nodes}/{total_nodes} nodes online, "
                f"{running_vms}/{total_vms} VMs running"
            )
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to get cluster resource summary: {e}")
            raise ProxmoxAPIException(f"Cluster resource summary failed: {e}")


# Import time for timestamp functionality
import time