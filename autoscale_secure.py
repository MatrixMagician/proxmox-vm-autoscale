"""
Secure VM Autoscaler with modern Python design patterns and security improvements.
"""
import logging
import logging.config
import time
import sys
import signal
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import json

from secure_config_loader import SecureConfigLoader, ConfigurationError
from config_models import VMAutoscaleConfig, ProxmoxHost, VirtualMachine
from secure_ssh_client import SecureSSHClient, SecurityException
from vm_manager import VMResourceManager
from host_resource_checker import HostResourceChecker
from secure_notification_manager import SecureNotificationManager


class VMAutoscaler:
    """
    Secure VM Autoscaler with enhanced security features:
    - Secure configuration loading with validation
    - Injection-proof SSH command execution
    - Proper credential handling
    - Enhanced error handling and logging
    - Graceful shutdown handling
    """

    def __init__(self, config_path: str, logging_config_path: Optional[str] = None, env_file: Optional[str] = None):
        """
        Initialize the VM Autoscaler.
        
        Args:
            config_path: Path to configuration file
            logging_config_path: Path to logging configuration file
            env_file: Path to environment variables file
        """
        self.config_path = config_path
        self.logging_config_path = logging_config_path
        self.env_file = env_file
        
        # Initialize configuration and logging
        self.config = self._load_configuration()
        self.logger = self._setup_logging()
        
        # Initialize notification manager
        self.notification_manager = SecureNotificationManager(self.config, self.logger)
        
        # Shutdown handling
        self.shutdown_event = threading.Event()
        self._setup_signal_handlers()
        
        # SSH connection pool
        self.ssh_connections: Dict[str, SecureSSHClient] = {}
        
        self.logger.info("VM Autoscaler initialized successfully")

    def _load_configuration(self) -> VMAutoscaleConfig:
        """Load and validate configuration."""
        try:
            config_loader = SecureConfigLoader(self.config_path, self.env_file)
            config = config_loader.load_config()
            
            # Log sanitized configuration summary
            summary = config_loader.get_sanitized_config_summary(config)
            print(f"Configuration loaded: {json.dumps(summary, indent=2)}")
            
            return config
        except Exception as e:
            logging.critical(f"Failed to load configuration: {e}")
            sys.exit(1)

    def _setup_logging(self) -> logging.Logger:
        """Setup secure logging configuration."""
        if self.logging_config_path and Path(self.logging_config_path).exists():
            try:
                with open(self.logging_config_path, 'r') as logging_file:
                    logging_config = json.load(logging_file)
                    logging.config.dictConfig(logging_config)
            except Exception as e:
                print(f"Failed to load logging config: {e}, using default configuration")
                self._setup_default_logging()
        else:
            self._setup_default_logging()
        
        return logging.getLogger("vm_autoscaler")

    def _setup_default_logging(self) -> None:
        """Setup default logging configuration."""
        # Ensure log directory exists
        log_file = Path(self.config.logging.log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging with security considerations
        logging.basicConfig(
            level=getattr(logging, self.config.logging.level),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.FileHandler(log_file, mode='a', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Set up log rotation for security (prevent log file growth attacks)
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        
        root_logger = logging.getLogger()
        # Remove default file handler and add rotating handler
        for handler in root_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler) and not isinstance(handler, RotatingFileHandler):
                root_logger.removeHandler(handler)
        root_logger.addHandler(file_handler)

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    @contextmanager
    def _get_ssh_connection(self, host: ProxmoxHost):
        """
        Context manager for SSH connections with proper cleanup.
        
        Args:
            host: Proxmox host configuration
            
        Yields:
            SecureSSHClient: Connected SSH client
        """
        ssh_client = None
        try:
            ssh_client = SecureSSHClient(
                host=host.host,
                user=host.ssh_user,
                password=host.get_ssh_password(),
                key_path=host.ssh_key,
                port=host.ssh_port,
                max_retries=3
            )
            ssh_client.connect()
            yield ssh_client
        except SecurityException as e:
            self.logger.error(f"Security error connecting to {host.name}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to connect to {host.name}: {e}")
            raise
        finally:
            if ssh_client:
                ssh_client.close()

    def process_vm(self, host: ProxmoxHost, vm: VirtualMachine) -> None:
        """
        Process a single VM for autoscaling with enhanced security.
        
        Args:
            host: Proxmox host configuration
            vm: Virtual machine configuration
        """
        try:
            with self._get_ssh_connection(host) as ssh_client:
                # Initialize managers with secure SSH client
                vm_manager = VMResourceManager(ssh_client, vm.vm_id, self._get_vm_config())
                host_checker = HostResourceChecker(ssh_client)
                
                # Check if VM is running
                if not vm_manager.is_vm_running():
                    self.logger.debug(f"VM {vm.vm_id} is not running. Skipping scaling.")
                    return

                # Check host resources first
                if not host_checker.check_host_resources(
                    self.config.host_limits.max_host_cpu_percent,
                    self.config.host_limits.max_host_ram_percent
                ):
                    self.logger.warning(f"Host {host.name} resources at limit. Skipping scaling.")
                    return

                # Get current resource usage
                current_cpu_usage, current_ram_usage = vm_manager.get_resource_usage()
                self.logger.info(
                    f"VM {vm.vm_id} current usage - CPU: {current_cpu_usage:.1f}%, "
                    f"RAM: {current_ram_usage:.1f}%"
                )

                # Perform scaling operations
                self._handle_scaling_operations(vm_manager, vm, current_cpu_usage, current_ram_usage)

        except SecurityException as e:
            error_msg = f"Security error processing VM {vm.vm_id} on host {host.name}: {e}"
            self.logger.error(error_msg)
            self.notification_manager.send_notification(
                f"Security alert: VM {vm.vm_id} processing failed",
                priority=10
            )
        except Exception as e:
            error_msg = f"Error processing VM {vm.vm_id} on host {host.name}: {e}"
            self.logger.error(error_msg)
            self.notification_manager.send_notification(
                f"VM {vm.vm_id} processing failed on {host.name}",
                priority=8
            )

    def _handle_scaling_operations(
        self, 
        vm_manager: VMResourceManager, 
        vm: VirtualMachine,
        cpu_usage: float, 
        ram_usage: float
    ) -> None:
        """
        Handle CPU and RAM scaling operations independently.
        
        Args:
            vm_manager: VM resource manager
            vm: VM configuration
            cpu_usage: Current CPU usage percentage
            ram_usage: Current RAM usage percentage
        """
        # Handle CPU scaling if enabled
        if vm.cpu_scaling:
            try:
                self._handle_cpu_scaling(vm_manager, vm.vm_id, cpu_usage)
            except Exception as e:
                self.logger.error(f"CPU scaling failed for VM {vm.vm_id}: {e}")

        # Handle RAM scaling if enabled
        if vm.ram_scaling:
            try:
                self._handle_ram_scaling(vm_manager, vm.vm_id, ram_usage)
            except Exception as e:
                self.logger.error(f"RAM scaling failed for VM {vm.vm_id}: {e}")

    def _handle_cpu_scaling(self, vm_manager: VMResourceManager, vm_id: int, cpu_usage: float) -> None:
        """Handle CPU scaling decisions."""
        cpu_thresholds = self.config.scaling_thresholds.cpu
        
        if cpu_usage > cpu_thresholds.high:
            if vm_manager.scale_cpu('up'):
                message = f"Scaled up CPU for VM {vm_id} due to high usage ({cpu_usage:.1f}%)"
                self.logger.info(message)
                self.notification_manager.send_notification(message, priority=7)
        elif cpu_usage < cpu_thresholds.low:
            if vm_manager.scale_cpu('down'):
                message = f"Scaled down CPU for VM {vm_id} due to low usage ({cpu_usage:.1f}%)"
                self.logger.info(message)
                self.notification_manager.send_notification(message, priority=5)

    def _handle_ram_scaling(self, vm_manager: VMResourceManager, vm_id: int, ram_usage: float) -> None:
        """Handle RAM scaling decisions."""
        ram_thresholds = self.config.scaling_thresholds.ram
        
        if ram_usage > ram_thresholds.high:
            if vm_manager.scale_ram('up'):
                message = f"Scaled up RAM for VM {vm_id} due to high usage ({ram_usage:.1f}%)"
                self.logger.info(message)
                self.notification_manager.send_notification(message, priority=7)
        elif ram_usage < ram_thresholds.low:
            if vm_manager.scale_ram('down'):
                message = f"Scaled down RAM for VM {vm_id} due to low usage ({ram_usage:.1f}%)"
                self.logger.info(message)
                self.notification_manager.send_notification(message, priority=5)

    def _get_vm_config(self) -> Dict[str, Any]:
        """Get VM configuration dictionary for compatibility."""
        return {
            'min_cores': self.config.scaling_limits.min_cores,
            'max_cores': self.config.scaling_limits.max_cores,
            'min_ram': self.config.scaling_limits.min_ram_mb,
            'max_ram': self.config.scaling_limits.max_ram_mb,
            'scale_cooldown': self.config.scale_cooldown
        }

    def run(self) -> None:
        """Main execution loop with enhanced error handling and security."""
        self.logger.info("Starting secure VM Autoscaler")
        
        try:
            while not self.shutdown_event.is_set():
                start_time = time.time()
                
                try:
                    self._process_all_vms()
                except Exception as e:
                    self.logger.error(f"Error in main processing loop: {e}")
                    self.notification_manager.send_notification(
                        f"VM Autoscaler encountered an error: {type(e).__name__}",
                        priority=9
                    )
                
                # Calculate sleep time accounting for processing duration
                processing_time = time.time() - start_time
                sleep_time = max(0, self.config.check_interval - processing_time)
                
                if sleep_time > 0:
                    self.logger.debug(f"Sleeping for {sleep_time:.1f} seconds")
                    if self.shutdown_event.wait(sleep_time):
                        break
                else:
                    self.logger.warning(
                        f"Processing took {processing_time:.1f}s, longer than "
                        f"check interval {self.config.check_interval}s"
                    )
        
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
        except Exception as e:
            self.logger.critical(f"Critical error in main loop: {e}")
            self.notification_manager.send_notification(
                f"VM Autoscaler critical error: {type(e).__name__}",
                priority=10
            )
        finally:
            self._cleanup()

    def _process_all_vms(self) -> None:
        """Process all configured VMs."""
        # Create host lookup for efficient access
        hosts_by_name = {host.name: host for host in self.config.proxmox_hosts}
        
        for vm in self.config.virtual_machines:
            if self.shutdown_event.is_set():
                break
                
            if not vm.scaling_enabled:
                self.logger.debug(f"Scaling disabled for VM {vm.vm_id}, skipping")
                continue
            
            host = hosts_by_name.get(vm.proxmox_host)
            if not host:
                self.logger.error(f"Host {vm.proxmox_host} not found for VM {vm.vm_id}")
                continue
            
            try:
                self.process_vm(host, vm)
            except Exception as e:
                self.logger.error(f"Failed to process VM {vm.vm_id}: {e}")

    def _cleanup(self) -> None:
        """Cleanup resources on shutdown."""
        self.logger.info("Performing cleanup...")
        
        # Close any remaining SSH connections
        for ssh_client in self.ssh_connections.values():
            try:
                ssh_client.close()
            except Exception as e:
                self.logger.error(f"Error closing SSH connection: {e}")
        
        self.ssh_connections.clear()
        self.logger.info("VM Autoscaler shutdown complete")


def main():
    """Entry point of the secure VM Autoscaler application."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Proxmox VM Autoscaler")
    parser.add_argument(
        "--config", 
        default="/usr/local/bin/vm_autoscale/config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--logging-config",
        default="/usr/local/bin/vm_autoscale/logging_config.json",
        help="Path to logging configuration file"
    )
    parser.add_argument(
        "--env-file",
        help="Path to environment variables file"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate configuration and exit"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize autoscaler
        autoscaler = VMAutoscaler(
            config_path=args.config,
            logging_config_path=args.logging_config,
            env_file=args.env_file
        )
        
        if args.validate_only:
            print("Configuration validation successful")
            sys.exit(0)
        
        # Run the autoscaler
        autoscaler.run()
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except SecurityException as e:
        print(f"Security error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Failed to start VM Autoscaler: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()