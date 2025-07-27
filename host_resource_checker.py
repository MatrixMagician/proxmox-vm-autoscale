import logging
import json
from typing import Tuple
from ssh_client import SecureSSHClient

class HostResourceChecker:
    """
    Secure host resource checker with injection protection.
    """

    def __init__(self, ssh_client: SecureSSHClient):
        """
        Initialize the HostResourceChecker with a secure SSH client.
        :param ssh_client: Instance of secure SSH client for executing remote commands.
        """
        self.ssh_client = ssh_client
        self.logger = logging.getLogger("host_resource_checker")

    def check_host_resources(self, max_host_cpu_percent: float, max_host_ram_percent: float) -> bool:
        """
        Check host CPU and RAM usage against specified thresholds.
        :param max_host_cpu_percent: Maximum allowable CPU usage percentage.
        :param max_host_ram_percent: Maximum allowable RAM usage percentage.
        :return: True if resources are within limits, False otherwise.
        """
        # Validate input parameters
        if not (0 <= max_host_cpu_percent <= 100):
            raise ValueError(f"Invalid max_host_cpu_percent: {max_host_cpu_percent}")
        if not (0 <= max_host_ram_percent <= 100):
            raise ValueError(f"Invalid max_host_ram_percent: {max_host_ram_percent}")
        
        try:
            # Use secure command execution to get host status
            output, error, exit_status = self.ssh_client.execute_command_list([
                "sh", "-c", "pvesh get /nodes/$(hostname)/status --output-format json"
            ])
            
            # Debug logging
            self.logger.debug(f"Host status command output: {output}")
            self.logger.debug(f"Error output: {error}")
            self.logger.debug(f"Exit status: {exit_status}")
            
            # Check for command execution errors
            if exit_status != 0:
                raise RuntimeError(f"Command failed with exit code {exit_status}: {error}")
                
            # Parse JSON response
            data = json.loads(output.strip())
            
            # Validate required fields in response
            if 'cpu' not in data or 'memory' not in data:
                raise KeyError("Missing 'cpu' or 'memory' in the command output.")
                
            # Extract and validate CPU usage
            cpu_value = data['cpu']
            if not isinstance(cpu_value, (int, float)) or not 0 <= cpu_value <= 1:
                raise ValueError(f"Invalid CPU value from host: {cpu_value}")
            host_cpu_usage = cpu_value * 100  # Convert to percentage
            
            # Extract and validate memory details
            memory_data = data['memory']
            if not isinstance(memory_data, dict):
                raise ValueError("Invalid memory data structure")
                
            total_mem = memory_data.get('total', 1)  # Avoid division by zero
            used_mem = memory_data.get('used', 0)
            cached_mem = memory_data.get('cached', 0)
            free_mem = memory_data.get('free', 0)
            
            # Validate memory values
            for mem_val, name in [(total_mem, 'total'), (used_mem, 'used'), (cached_mem, 'cached'), (free_mem, 'free')]:
                if not isinstance(mem_val, (int, float)) or mem_val < 0:
                    raise ValueError(f"Invalid {name} memory value: {mem_val}")
            
            # Calculate RAM usage as a percentage
            if total_mem == 0:
                raise ValueError("Total memory cannot be zero")
            available_mem = free_mem + cached_mem
            host_ram_usage = ((total_mem - available_mem) / total_mem) * 100
            
            # Validate calculated usage values
            if not (0 <= host_cpu_usage <= 100):
                raise ValueError(f"Calculated CPU usage out of range: {host_cpu_usage}%")
            if not (0 <= host_ram_usage <= 100):
                raise ValueError(f"Calculated RAM usage out of range: {host_ram_usage}%")
            
            # Log resource usage
            self.logger.info(f"Host CPU Usage: {host_cpu_usage:.2f}%, "
                             f"Host RAM Usage: {host_ram_usage:.2f}%")
            
            # Check CPU usage threshold
            if host_cpu_usage > max_host_cpu_percent:
                self.logger.warning(f"Host CPU usage exceeds maximum allowed limit: "
                                    f"{host_cpu_usage:.2f}% > {max_host_cpu_percent}%")
                return False
                
            # Check RAM usage threshold
            if host_ram_usage > max_host_ram_percent:
                self.logger.warning(f"Host RAM usage exceeds maximum allowed limit: "
                                    f"{host_ram_usage:.2f}% > {max_host_ram_percent}%")
                return False
                
            # Resources are within limits
            return True
            
        except json.JSONDecodeError as json_err:
            self.logger.error(f"Failed to parse JSON output: {str(json_err)}")
            # Don't log the raw output as it might contain sensitive data
            raise RuntimeError("Invalid JSON response from host status command")
        except (KeyError, ValueError) as data_err:
            self.logger.error(f"Invalid data in host status response: {str(data_err)}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to check host resources: {str(e)}")
            raise