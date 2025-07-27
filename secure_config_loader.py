"""
Secure configuration loader with validation and credential protection.
"""
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from dotenv import load_dotenv
from config_models import VMAutoscaleConfig


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass


class SecureConfigLoader:
    """
    Secure configuration loader that:
    - Validates configuration using Pydantic models
    - Loads credentials from environment variables
    - Prevents credential exposure in logs
    - Validates file permissions
    """

    def __init__(self, config_path: str, env_file: Optional[str] = None):
        self.config_path = Path(config_path)
        self.env_file = env_file
        self.logger = logging.getLogger("secure_config_loader")
        
        # Load environment variables if env file specified
        if env_file and Path(env_file).exists():
            load_dotenv(env_file)

    def load_config(self) -> VMAutoscaleConfig:
        """
        Load and validate configuration file.
        
        Returns:
            VMAutoscaleConfig: Validated configuration object
            
        Raises:
            ConfigurationError: If configuration is invalid or insecure
        """
        # Validate config file exists and has proper permissions
        self._validate_config_file()
        
        # Load raw configuration
        raw_config = self._load_raw_config()
        
        # Process sensitive values
        processed_config = self._process_sensitive_values(raw_config)
        
        # Validate using Pydantic model
        try:
            config = VMAutoscaleConfig(**processed_config)
            self.logger.info("Configuration loaded and validated successfully")
            return config
        except Exception as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")

    def _validate_config_file(self) -> None:
        """Validate configuration file exists and has secure permissions."""
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        # Check file permissions (should not be world-readable for security)
        file_mode = self.config_path.stat().st_mode
        if file_mode & 0o044:  # Check if group or others have read permission
            self.logger.warning(
                f"Configuration file {self.config_path} has overly permissive permissions. "
                f"Consider using 'chmod 600 {self.config_path}' for better security."
            )

    def _load_raw_config(self) -> Dict[str, Any]:
        """Load raw configuration from YAML file."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as config_file:
                config = yaml.safe_load(config_file)
            
            if not isinstance(config, dict):
                raise ConfigurationError("Configuration file must contain a YAML object")
            
            return config
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to read configuration file: {e}")

    def _process_sensitive_values(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process sensitive values by resolving environment variable references.
        
        Supports format: ${ENV_VAR_NAME} or ${ENV_VAR_NAME:default_value}
        """
        processed_config = {}
        
        for key, value in config.items():
            if key == 'proxmox_hosts':
                processed_config[key] = self._process_host_credentials(value)
            elif key == 'alerts':
                processed_config[key] = self._process_alert_credentials(value)
            elif key == 'gotify':
                processed_config[key] = self._process_gotify_credentials(value)
            else:
                processed_config[key] = value
        
        return processed_config

    def _process_host_credentials(self, hosts: list) -> list:
        """Process host credentials, resolving environment variables."""
        processed_hosts = []
        
        for host in hosts:
            if not isinstance(host, dict):
                raise ConfigurationError("Each host must be a dictionary")
            
            processed_host = host.copy()
            
            # Process SSH password
            if 'ssh_password' in host:
                processed_host['ssh_password'] = self._resolve_env_var(
                    host['ssh_password'], 
                    f"SSH password for host {host.get('name', 'unknown')}"
                )
            
            processed_hosts.append(processed_host)
        
        return processed_hosts

    def _process_alert_credentials(self, alerts: dict) -> dict:
        """Process alert credentials, resolving environment variables."""
        if not isinstance(alerts, dict):
            return alerts
        
        processed_alerts = alerts.copy()
        
        # Process SMTP password
        if 'smtp_password' in alerts:
            processed_alerts['smtp_password'] = self._resolve_env_var(
                alerts['smtp_password'],
                "SMTP password"
            )
        
        return processed_alerts

    def _process_gotify_credentials(self, gotify: dict) -> dict:
        """Process Gotify credentials, resolving environment variables."""
        if not isinstance(gotify, dict):
            return gotify
        
        processed_gotify = gotify.copy()
        
        # Process app token
        if 'app_token' in gotify:
            processed_gotify['app_token'] = self._resolve_env_var(
                gotify['app_token'],
                "Gotify app token"
            )
        
        return processed_gotify

    def _resolve_env_var(self, value: Any, description: str) -> Any:
        """
        Resolve environment variable reference.
        
        Supports formats:
        - ${ENV_VAR} - required env var
        - ${ENV_VAR:default} - env var with default value
        - literal value - returned as-is
        """
        if not isinstance(value, str):
            return value
        
        # Check for environment variable reference
        if value.startswith('${') and value.endswith('}'):
            env_spec = value[2:-1]  # Remove ${ and }
            
            # Check for default value
            if ':' in env_spec:
                env_var, default_value = env_spec.split(':', 1)
                env_value = os.getenv(env_var.strip(), default_value)
            else:
                env_var = env_spec.strip()
                env_value = os.getenv(env_var)
                
                if env_value is None:
                    raise ConfigurationError(
                        f"Required environment variable '{env_var}' not set for {description}"
                    )
            
            if env_value:
                self.logger.debug(f"Resolved environment variable for {description}")
            else:
                self.logger.warning(f"Empty value for {description}")
            
            return env_value
        
        # Return literal value
        return value

    def get_sanitized_config_summary(self, config: VMAutoscaleConfig) -> Dict[str, Any]:
        """
        Get a sanitized summary of the configuration for logging.
        Removes sensitive information like passwords and tokens.
        """
        summary = {
            'hosts_count': len(config.proxmox_hosts),
            'vms_count': len(config.virtual_machines),
            'check_interval': config.check_interval,
            'scale_cooldown': config.scale_cooldown,
            'cpu_thresholds': {
                'high': config.scaling_thresholds.cpu.high,
                'low': config.scaling_thresholds.cpu.low
            },
            'ram_thresholds': {
                'high': config.scaling_thresholds.ram.high,
                'low': config.scaling_thresholds.ram.low
            },
            'resource_limits': {
                'min_cores': config.scaling_limits.min_cores,
                'max_cores': config.scaling_limits.max_cores,
                'min_ram_mb': config.scaling_limits.min_ram_mb,
                'max_ram_mb': config.scaling_limits.max_ram_mb
            },
            'notifications': {
                'gotify_enabled': config.gotify.enabled,
                'email_enabled': config.alerts.email_enabled
            }
        }
        
        return summary