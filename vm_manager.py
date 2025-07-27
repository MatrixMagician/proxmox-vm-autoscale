import logging
import re
import time
import threading
from typing import Tuple, Optional
from secure_ssh_client import SecureSSHClient, SecurityException


class VMResourceManager:
    """Secure VM resource manager with injection protection."""
    
    def __init__(self, ssh_client: SecureSSHClient, vm_id: int, config: dict):
        self.ssh_client = ssh_client
        self.vm_id = self._validate_vm_id(vm_id)
        self.config = config
        self.logger = logging.getLogger(f"vm_resource_manager.{vm_id}")
        self.last_scale_time = 0
        self.scale_cooldown = self.config.get("scale_cooldown", 300)
        self.scale_lock = threading.Lock()
    
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

    def _get_command_output(self, output):
        """Helper method to properly handle command output that might be a tuple."""
        if isinstance(output, tuple):
            # Assuming the first element contains the stdout
            return str(output[0]).strip() if output and output[0] is not None else ""
        return str(output).strip() if output is not None else ""

    def is_vm_running(self, retries: int = 3, delay: int = 5) -> bool:
        """Check if the VM is running with retries and improved error handling."""
        for attempt in range(1, retries + 1):
            try:
                stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                    "qm", "status", self.vm_id, "--verbose"
                )
                self.logger.debug(f"VM status command output: {stdout}")
        
                if "status: running" in stdout.lower():
                    self.logger.info(f"VM {self.vm_id} is running.")
                    return True
                elif "status:" in stdout.lower():
                    self.logger.info(f"VM {self.vm_id} is not running.")
                    return False
                else:
                    self.logger.warning(
                        f"Unexpected output while checking VM status: {stdout}"
                    )
            except Exception as e:
                self.logger.warning(
                    f"Attempt {attempt}/{retries} failed to check VM status: {e}. Retrying..."
                )
                time.sleep(delay * attempt)  # Exponential backoff
        
        self.logger.error(
            f"Unable to determine status of VM {self.vm_id} after {retries} attempts."
        )
        return False

    def get_resource_usage(self) -> Tuple[float, float]:
        """Retrieve CPU and RAM usage as percentages."""
        try:
            if not self.is_vm_running():
                return 0.0, 0.0
            
            # Use secure command execution to get resource usage
            stdout, stderr, exit_code = self.ssh_client.execute_command_list([
                "sh", "-c", 
                f"pvesh get /cluster/resources | grep 'qemu/{self.vm_id}' | awk -F '│' '{{print $6, $15, $16}}'"
            ])
            
            self.logger.debug(f"VM resource usage output: {stdout}")
            cpu_usage = self._parse_cpu_usage(stdout)
            ram_usage = self._parse_ram_usage(stdout)
            return cpu_usage, ram_usage
        except Exception as e:
            self.logger.error(f"Failed to retrieve resource usage: {e}")
            return 0.0, 0.0

    def can_scale(self):
        """Determine if scaling can occur using a lock to avoid race conditions."""
        with self.scale_lock:
            current_time = time.time()
            if current_time - self.last_scale_time < self.scale_cooldown:
                return False
            self.last_scale_time = current_time
            return True

    def scale_cpu(self, direction: str) -> bool:
        """Scale the CPU cores and vCPUs of the VM."""
        if direction not in ['up', 'down']:
            raise ValueError(f"Invalid scaling direction: {direction}")
        
        if not self.can_scale():
            return False

        try:
            current_cores = self._get_current_cores()
            max_cores = self._get_max_cores()
            min_cores = self._get_min_cores()
            current_vcpus = self._get_current_vcpus()

            self.last_scale_time = time.time()
            if direction == "up" and current_cores < max_cores:
                self._scale_cpu_up(current_cores, current_vcpus)
                return True
            elif direction == "down" and current_cores > min_cores:
                self._scale_cpu_down(current_cores, current_vcpus)
                return True
            else:
                self.logger.info("No CPU scaling required.")
                return False
        except Exception as e:
            self.logger.error(f"Failed to scale CPU: {e}")
            raise

    def scale_ram(self, direction: str) -> bool:
        """Scale the RAM of the VM."""
        if direction not in ['up', 'down']:
            raise ValueError(f"Invalid scaling direction: {direction}")
        
        if not self.can_scale():
            return False

        try:
            current_ram = self._get_current_ram()
            max_ram = self._get_max_ram()
            min_ram = self._get_min_ram()

            self.last_scale_time = time.time()
            if direction == "up" and current_ram < max_ram:
                new_ram = min(current_ram + 512, max_ram)
                self._set_ram(new_ram)
                return True
            elif direction == "down" and current_ram > min_ram:
                new_ram = max(current_ram - 512, min_ram)
                self._set_ram(new_ram)
                return True
            else:
                self.logger.info("No RAM scaling required.")
            return False
        except Exception as e:
            self.logger.error(f"Failed to scale RAM: {e}")
            raise

    def _parse_cpu_usage(self, output: str) -> float:
        """Parse CPU usage from VM status output."""
        try:
            percentage_cpu_match = re.search(r"^\s*(\d+(?:\.\d+)?)%", output.strip())
            if percentage_cpu_match:
                cpu_usage = float(percentage_cpu_match.group(1))
                # Validate reasonable CPU usage range
                if 0 <= cpu_usage <= 100:
                    return cpu_usage
                self.logger.warning(f"CPU usage out of range: {cpu_usage}%")
            self.logger.warning("CPU usage not found in output.")
            return 0.0
        except Exception as e:
            self.logger.error(f"Error parsing CPU usage: {e}")
            return 0.0
    
    def _convert_to_gib(self, value, unit):
        """ Converts memory units to GiB. """
        unit = unit.lower()
        if unit == 'gib':
            return value
        elif unit == 'mib':
            return value / 1024  # Convert MiB to GiB
        else:
            self.logger.warning(f"Unknown memory unit '{unit}'. Assuming GiB.")
            return value  # Assume GiB if unit is unknown

    def _parse_ram_usage(self, output: str) -> float:
        """Parse RAM usage from VM status output."""
        try:
            output_str = output.strip()
            self.logger.debug(f"Processing RAM usage output: '{output_str}'")
            # ----------------------------
            # Extract Memory Values
            # ----------------------------
            # Pattern Explanation:
            # - (\d+(?:\.\d+)?)\s+(GiB|MiB) : Capture first memory value and its unit
            # - \s+                         : Match one or more whitespace characters
            # - (\d+(?:\.\d+)?)\s+(GiB|MiB) : Capture second memory value and its unit
            pattern_memory = r"(\d+(?:\.\d+)?)\s+(GiB|MiB)\s+(\d+(?:\.\d+)?)\s+(GiB|MiB)"
            memory_match = re.search(pattern_memory, output_str)
            if memory_match:
                max_mem_value = float(memory_match.group(1))
                max_mem_unit = memory_match.group(2)
                used_mem_value = float(memory_match.group(3))
                used_mem_unit = memory_match.group(4)

                self.logger.debug(f"Extracted Max Memory: {max_mem_value} {max_mem_unit}")
                self.logger.debug(f"Extracted Used Memory: {used_mem_value} {used_mem_unit}")

                # Convert memory values to GiB
                max_mem_gib = self._convert_to_gib(max_mem_value, max_mem_unit)
                used_mem_gib = self._convert_to_gib(used_mem_value, used_mem_unit)

                self.logger.debug(f"Converted Max Memory: {max_mem_gib} GiB")
                self.logger.debug(f"Converted Used Memory: {used_mem_gib} GiB")

                if max_mem_gib == 0:
                    self.logger.warning("Maximum memory is zero. Cannot compute usage percentage.")
                    return 0.0

                # Calculate RAM usage percentage based on memory values
                usage_percentage = (used_mem_gib / max_mem_gib) * 100
                self.logger.debug(f"Calculated RAM Usage: {usage_percentage:.2f}%")
                return usage_percentage
            else:
                self.logger.warning("RAM memory values not found in output.")
                return 0.0

        except Exception as e:
            self.logger.error(f"Error parsing RAM usage: {e}")
            return 0.0

    def _get_current_vcpus(self) -> int:
        """Retrieve current vCPUs assigned to the VM."""
        try:
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "config", self.vm_id
            )
            match = re.search(r"vcpus:\s*(\d+)", stdout)
            vcpus = int(match.group(1)) if match else 1
            return self._validate_resource_value(vcpus, 1, 128, "vCPUs")
        except Exception as e:
            self.logger.error(f"Failed to retrieve vCPUs: {e}")
            return 1

    def _get_current_cores(self) -> int:
        """Retrieve current CPU cores assigned to the VM."""
        try:
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "config", self.vm_id
            )
            match = re.search(r"cores:\s*(\d+)", stdout)
            cores = int(match.group(1)) if match else 1
            return self._validate_resource_value(cores, 1, 128, "cores")
        except Exception as e:
            self.logger.error(f"Failed to retrieve CPU cores: {e}")
            return 1

    def _get_max_cores(self):
        """Retrieve maximum allowed CPU cores."""
        return self.config.get("max_cores", 8)

    def _get_min_cores(self):
        """Retrieve minimum allowed CPU cores."""
        return self.config.get("min_cores", 1)

    def _get_current_ram(self) -> int:
        """Retrieve current RAM assigned to the VM."""
        try:
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "config", self.vm_id
            )
            match = re.search(r"memory:\s*(\d+)", stdout)
            ram = int(match.group(1)) if match else 512
            return self._validate_resource_value(ram, 512, 1048576, "RAM")
        except Exception as e:
            self.logger.error(f"Failed to retrieve current RAM: {e}")
            return 512

    def _get_max_ram(self):
        """Retrieve maximum allowed RAM."""
        return self.config.get("max_ram", 16384)

    def _get_min_ram(self):
        """Retrieve minimum allowed RAM."""
        return self.config.get("min_ram", 512)

    def _set_ram(self, ram: int) -> None:
        """Set the RAM for the VM."""
        try:
            validated_ram = self._validate_resource_value(ram, 512, 1048576, "RAM")
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "set", self.vm_id, "-memory", validated_ram
            )
            self.logger.info(f"RAM set to {validated_ram} MB for VM {self.vm_id}.")
        except Exception as e:
            self.logger.error(f"Failed to set RAM to {ram}: {e}")
            raise

    def _scale_cpu_up(self, current_cores, current_vcpus):
        """Helper method to scale CPU up."""
        new_cores = current_cores + 1
        self._set_cores(new_cores)
        new_vcpus = min(current_vcpus + 1, new_cores)
        self._set_vcpus(new_vcpus)

    def _scale_cpu_down(self, current_cores, current_vcpus):
        """Helper method to scale CPU down."""
        new_vcpus = max(current_vcpus - 1, 1)
        self._set_vcpus(new_vcpus)
        new_cores = current_cores - 1
        self._set_cores(new_cores)

    def _set_cores(self, cores: int) -> None:
        """Set the CPU cores for the VM."""
        try:
            validated_cores = self._validate_resource_value(cores, 1, 128, "cores")
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "set", self.vm_id, "-cores", validated_cores
            )
            self.logger.info(f"CPU cores set to {validated_cores} for VM {self.vm_id}.")
        except Exception as e:
            self.logger.error(f"Failed to set CPU cores to {cores}: {e}")
            raise

    def _set_vcpus(self, vcpus: int) -> None:
        """Set the vCPUs for the VM."""
        try:
            validated_vcpus = self._validate_resource_value(vcpus, 1, 128, "vCPUs")
            stdout, stderr, exit_code = self.ssh_client.execute_command_safe(
                "qm", "set", self.vm_id, "-vcpus", validated_vcpus
            )
            self.logger.info(f"vCPUs set to {validated_vcpus} for VM {self.vm_id}.")
        except Exception as e:
            self.logger.error(f"Failed to set vCPUs to {vcpus}: {e}")
            raise