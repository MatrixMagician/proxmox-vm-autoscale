"""
Secure SSH client with proper security measures and command injection protection.
"""
import logging
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple, Union
import paramiko
from paramiko.ssh_exception import SSHException, AuthenticationException


class SecurityException(Exception):
    """Custom exception for security-related errors."""
    pass


class SecureSSHClient:
    """
    Secure SSH client with enhanced security features:
    - Host key verification
    - Command injection protection
    - Connection retry logic with exponential backoff
    - Proper credential handling
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        known_hosts_file: Optional[str] = None,
        max_retries: int = 3,
        backoff_factor: float = 1.0
    ):
        self.host = host
        self.user = user
        self.password = password
        self.key_path = key_path
        self.port = port
        self.known_hosts_file = known_hosts_file or os.path.expanduser('~/.ssh/known_hosts')
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        
        self.logger = logging.getLogger(f"secure_ssh_client.{host}")
        self.client: Optional[paramiko.SSHClient] = None
        
        # Validate initialization parameters
        self._validate_init_params()

    def _validate_init_params(self) -> None:
        """Validate initialization parameters."""
        if not self.password and not self.key_path:
            raise ValueError("Either password or key_path must be provided")
        
        if self.key_path and not Path(self.key_path).exists():
            raise FileNotFoundError(f"SSH key file not found: {self.key_path}")
        
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid port number: {self.port}")

    def _verify_host_key(self, hostname: str, key: paramiko.PKey) -> None:
        """
        Verify host key against known_hosts file.
        Raises SecurityException if verification fails.
        """
        if not Path(self.known_hosts_file).exists():
            # Create empty known_hosts file if it doesn't exist
            Path(self.known_hosts_file).parent.mkdir(parents=True, exist_ok=True)
            Path(self.known_hosts_file).touch(mode=0o600)
            self.logger.warning(f"Created empty known_hosts file: {self.known_hosts_file}")
            return

        try:
            known_hosts = paramiko.util.load_host_keys(self.known_hosts_file)
        except Exception as e:
            raise SecurityException(f"Failed to load known_hosts file: {e}")

        # Check if host is in known_hosts
        if hostname not in known_hosts:
            raise SecurityException(
                f"Host {hostname} not found in known_hosts file. "
                f"Please add the host key manually or use ssh-keyscan."
            )

        # Verify the key matches
        host_keys = known_hosts[hostname]
        key_type = key.get_name()
        
        if key_type not in host_keys:
            raise SecurityException(f"Host key type {key_type} not found for {hostname}")
        
        if not host_keys[key_type].asbytes() == key.asbytes():
            raise SecurityException(f"Host key verification failed for {hostname}")

        self.logger.debug(f"Host key verification successful for {hostname}")

    def connect(self) -> None:
        """Establish secure SSH connection with host key verification."""
        if self.is_connected():
            self.logger.debug(f"Already connected to {self.host}")
            return

        for attempt in range(1, self.max_retries + 1):
            try:
                self.client = paramiko.SSHClient()
                
                # Set strict host key policy for security
                self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
                
                # Custom host key verification
                def check_host_key(hostname, key):
                    self._verify_host_key(hostname, key)
                    return True

                # Load system and user known_hosts
                self.client.load_system_host_keys()
                self.client.load_host_keys(self.known_hosts_file)

                # Connect with appropriate authentication method
                connect_kwargs = {
                    'hostname': self.host,
                    'username': self.user,
                    'port': self.port,
                    'timeout': 30,
                    'auth_timeout': 30,
                    'banner_timeout': 30
                }

                if self.password:
                    connect_kwargs['password'] = self.password
                elif self.key_path:
                    try:
                        # Try different key types
                        for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
                            try:
                                private_key = key_class.from_private_key_file(self.key_path)
                                connect_kwargs['pkey'] = private_key
                                break
                            except paramiko.PasswordRequiredException:
                                raise SecurityException("SSH key is encrypted but no passphrase provided")
                            except Exception:
                                continue
                        else:
                            raise SecurityException(f"Unable to load SSH key: {self.key_path}")
                    except Exception as e:
                        raise SecurityException(f"SSH key loading failed: {e}")

                self.client.connect(**connect_kwargs)
                self.logger.info(f"Successfully connected to {self.host}:{self.port}")
                return

            except AuthenticationException as e:
                self.logger.error(f"Authentication failed for {self.host}: {e}")
                raise SecurityException(f"Authentication failed: {e}")
            
            except SecurityException:
                # Re-raise security exceptions without retry
                raise
            
            except Exception as e:
                if attempt >= self.max_retries:
                    self.logger.error(f"Failed to connect to {self.host} after {attempt} attempts: {e}")
                    raise ConnectionError(f"Connection failed after {attempt} attempts: {e}")
                
                sleep_time = self.backoff_factor * (2 ** (attempt - 1))
                self.logger.warning(
                    f"Connection attempt {attempt} failed for {self.host}: {e}. "
                    f"Retrying in {sleep_time} seconds..."
                )
                time.sleep(sleep_time)

    def execute_command_list(
        self,
        command_list: List[str],
        timeout: int = 30,
        check_exit_code: bool = True
    ) -> Tuple[str, str, int]:
        """
        Execute a command using a list of arguments to prevent injection.
        
        Args:
            command_list: List of command arguments (safer than string concatenation)
            timeout: Command timeout in seconds
            check_exit_code: Whether to raise exception on non-zero exit code
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not command_list:
            raise ValueError("Command list cannot be empty")
        
        # Validate command components to prevent injection
        for arg in command_list:
            self._validate_command_argument(str(arg))
        
        # Join arguments safely (no shell interpretation)
        command = ' '.join(f'"{arg}"' if ' ' in str(arg) else str(arg) for arg in command_list)
        
        return self._execute_command_internal(command, timeout, check_exit_code)

    def execute_command_safe(
        self,
        base_command: str,
        *args: Union[str, int],
        timeout: int = 30,
        check_exit_code: bool = True
    ) -> Tuple[str, str, int]:
        """
        Execute a command with validated arguments.
        
        Args:
            base_command: Base command (e.g., 'qm', 'pvesh')
            *args: Command arguments
            timeout: Command timeout in seconds
            check_exit_code: Whether to raise exception on non-zero exit code
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        command_list = [base_command] + [str(arg) for arg in args]
        return self.execute_command_list(command_list, timeout, check_exit_code)

    def _validate_command_argument(self, arg: str) -> None:
        """
        Validate command argument to prevent injection attacks.
        
        Args:
            arg: Command argument to validate
            
        Raises:
            SecurityException: If argument contains suspicious characters
        """
        # Block obviously dangerous characters and patterns
        dangerous_chars = [';', '|', '&', '$(', '`', '\n', '\r']
        dangerous_patterns = ['&&', '||', '>>', '<<', '/dev/', '/proc/']
        
        for char in dangerous_chars:
            if char in arg:
                raise SecurityException(f"Potentially dangerous character '{char}' in command argument: {arg}")
        
        for pattern in dangerous_patterns:
            if pattern in arg:
                raise SecurityException(f"Potentially dangerous pattern '{pattern}' in command argument: {arg}")
        
        # Additional validation for specific argument types
        if arg.startswith('-'):
            # Validate command line options
            if not arg.replace('-', '').replace('_', '').isalnum():
                raise SecurityException(f"Invalid command line option format: {arg}")

    def _execute_command_internal(
        self,
        command: str,
        timeout: int,
        check_exit_code: bool
    ) -> Tuple[str, str, int]:
        """Internal command execution with retry logic."""
        if not self.is_connected():
            raise ConnectionError("Not connected to SSH server")

        for attempt in range(1, self.max_retries + 1):
            try:
                self.logger.debug(f"Executing command on {self.host}: {command}")
                
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                
                stdout_data = stdout.read().decode('utf-8', errors='replace').strip()
                stderr_data = stderr.read().decode('utf-8', errors='replace').strip()
                
                if check_exit_code and exit_code != 0:
                    error_msg = f"Command failed with exit code {exit_code}: {stderr_data}"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)
                
                self.logger.debug(f"Command completed successfully on {self.host}")
                return stdout_data, stderr_data, exit_code
                
            except Exception as e:
                if attempt >= self.max_retries:
                    self.logger.error(f"Command execution failed after {attempt} attempts: {e}")
                    raise
                
                self.logger.warning(f"Command execution attempt {attempt} failed: {e}. Retrying...")
                
                # Try to reconnect
                try:
                    self.close()
                    self.connect()
                except Exception as reconnect_error:
                    self.logger.error(f"Reconnection failed: {reconnect_error}")
                
                time.sleep(self.backoff_factor * attempt)

    def is_connected(self) -> bool:
        """Check if SSH connection is active."""
        return (
            self.client is not None 
            and self.client.get_transport() is not None
            and self.client.get_transport().is_active()
        )

    def close(self) -> None:
        """Close SSH connection."""
        if self.client:
            try:
                self.client.close()
                self.logger.debug(f"SSH connection closed for {self.host}")
            except Exception as e:
                self.logger.error(f"Error closing SSH connection to {self.host}: {e}")
            finally:
                self.client = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager exit."""
        self.close()

    def __del__(self):
        """Destructor to ensure connection cleanup."""
        self.close()