"""
Configuration models using Pydantic for validation and type safety.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict


class CPUThresholds(BaseModel):
    """CPU scaling thresholds configuration."""
    high: float = Field(ge=0, le=100, description="CPU usage percentage to trigger scale up")
    low: float = Field(ge=0, le=100, description="CPU usage percentage to trigger scale down")

    @field_validator('high', 'low')
    @classmethod
    def validate_percentage(cls, v: float) -> float:
        if not 0 <= v <= 100:
            raise ValueError('Percentage must be between 0 and 100')
        return v


class RAMThresholds(BaseModel):
    """RAM scaling thresholds configuration."""
    high: float = Field(ge=0, le=100, description="RAM usage percentage to trigger scale up")
    low: float = Field(ge=0, le=100, description="RAM usage percentage to trigger scale down")

    @field_validator('high', 'low')
    @classmethod
    def validate_percentage(cls, v: float) -> float:
        if not 0 <= v <= 100:
            raise ValueError('Percentage must be between 0 and 100')
        return v


class ScalingThresholds(BaseModel):
    """Combined scaling thresholds."""
    cpu: CPUThresholds
    ram: RAMThresholds


class ScalingLimits(BaseModel):
    """Resource limits for scaling operations."""
    min_cores: int = Field(ge=1, le=128, description="Minimum CPU cores")
    max_cores: int = Field(ge=1, le=128, description="Maximum CPU cores")
    min_ram_mb: int = Field(ge=512, le=1048576, description="Minimum RAM in MB")
    max_ram_mb: int = Field(ge=512, le=1048576, description="Maximum RAM in MB")

    @field_validator('max_cores')
    @classmethod
    def validate_max_cores(cls, v: int, info) -> int:
        if 'min_cores' in info.data and v < info.data['min_cores']:
            raise ValueError('max_cores must be greater than or equal to min_cores')
        return v

    @field_validator('max_ram_mb')
    @classmethod
    def validate_max_ram(cls, v: int, info) -> int:
        if 'min_ram_mb' in info.data and v < info.data['min_ram_mb']:
            raise ValueError('max_ram_mb must be greater than or equal to min_ram_mb')
        return v


class ProxmoxHost(BaseModel):
    """Proxmox host configuration with secure credential handling."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    name: str = Field(min_length=1, description="Host identifier")
    host: str = Field(min_length=1, description="Hostname or IP address")
    ssh_user: str = Field(min_length=1, description="SSH username")
    ssh_password: Optional[str] = Field(default=None, description="SSH password (use env var)")
    ssh_key: Optional[str] = Field(default=None, description="Path to SSH private key")
    ssh_port: int = Field(default=22, ge=1, le=65535, description="SSH port")

    @field_validator('host')
    @classmethod
    def validate_host(cls, v: str) -> str:
        # Basic validation for IP addresses and hostnames
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not (re.match(ip_pattern, v) or re.match(hostname_pattern, v)):
            raise ValueError('Invalid host format')
        return v

    @field_validator('ssh_key')
    @classmethod
    def validate_ssh_key(cls, v: Optional[str]) -> Optional[str]:
        if v and not Path(v).exists():
            raise ValueError(f'SSH key file does not exist: {v}')
        return v

    def get_ssh_password(self) -> Optional[str]:
        """Get SSH password from environment variable if not directly specified."""
        if self.ssh_password:
            # Check if it's an environment variable reference
            if self.ssh_password.startswith('${') and self.ssh_password.endswith('}'):
                env_var = self.ssh_password[2:-1]
                return os.getenv(env_var)
            return self.ssh_password
        return None

    def validate_credentials(self) -> None:
        """Validate that either password or key is provided."""
        password = self.get_ssh_password()
        if not password and not self.ssh_key:
            raise ValueError(f"Host {self.name}: Either ssh_password or ssh_key must be provided")


class VirtualMachine(BaseModel):
    """Virtual machine configuration."""
    vm_id: Union[int, str] = Field(description="VM ID")
    proxmox_host: str = Field(min_length=1, description="Associated Proxmox host name")
    scaling_enabled: bool = Field(default=True, description="Enable/disable scaling for this VM")
    cpu_scaling: bool = Field(default=True, description="Enable CPU scaling")
    ram_scaling: bool = Field(default=True, description="Enable RAM scaling")

    @field_validator('vm_id')
    @classmethod
    def validate_vm_id(cls, v: Union[int, str]) -> int:
        """Validate and convert VM ID to integer."""
        try:
            vm_id_int = int(v)
        except ValueError:
            raise ValueError(f'VM ID must be a valid integer: {v}')
        
        if not 100 <= vm_id_int <= 999999:
            raise ValueError(f'VM ID must be between 100 and 999999: {vm_id_int}')
        
        return vm_id_int


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="/var/log/vm_autoscale.log", description="Log file path")

    @field_validator('level')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if v.upper() not in valid_levels:
            raise ValueError(f'Invalid log level: {v}. Must be one of {valid_levels}')
        return v.upper()


class AlertsConfig(BaseModel):
    """Email alerts configuration."""
    email_enabled: bool = Field(default=False, description="Enable email notifications")
    email_recipient: Optional[str] = Field(default=None, description="Email recipient")
    smtp_server: Optional[str] = Field(default=None, description="SMTP server")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP port")
    smtp_user: Optional[str] = Field(default=None, description="SMTP username")
    smtp_password: Optional[str] = Field(default=None, description="SMTP password (use env var)")

    def get_smtp_password(self) -> Optional[str]:
        """Get SMTP password from environment variable if not directly specified."""
        if self.smtp_password:
            if self.smtp_password.startswith('${') and self.smtp_password.endswith('}'):
                env_var = self.smtp_password[2:-1]
                return os.getenv(env_var)
            return self.smtp_password
        return None


class GotifyConfig(BaseModel):
    """Gotify notifications configuration."""
    enabled: bool = Field(default=False, description="Enable Gotify notifications")
    server_url: Optional[str] = Field(default=None, description="Gotify server URL")
    app_token: Optional[str] = Field(default=None, description="Gotify app token (use env var)")
    priority: int = Field(default=5, ge=1, le=10, description="Notification priority")

    def get_app_token(self) -> Optional[str]:
        """Get app token from environment variable if not directly specified."""
        if self.app_token:
            if self.app_token.startswith('${') and self.app_token.endswith('}'):
                env_var = self.app_token[2:-1]
                return os.getenv(env_var)
            return self.app_token
        return None


class HostLimits(BaseModel):
    """Host resource limits."""
    max_host_cpu_percent: float = Field(default=90, ge=0, le=100, description="Max host CPU usage %")
    max_host_ram_percent: float = Field(default=90, ge=0, le=100, description="Max host RAM usage %")


class VMAutoscaleConfig(BaseModel):
    """Main configuration model for VM Autoscale."""
    scaling_thresholds: ScalingThresholds
    scaling_limits: ScalingLimits
    check_interval: int = Field(default=300, ge=30, le=3600, description="Check interval in seconds")
    proxmox_hosts: List[ProxmoxHost] = Field(min_length=1, description="List of Proxmox hosts")
    virtual_machines: List[VirtualMachine] = Field(min_length=1, description="List of VMs to manage")
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    gotify: GotifyConfig = Field(default_factory=GotifyConfig)
    host_limits: HostLimits = Field(default_factory=HostLimits)
    scale_cooldown: int = Field(default=300, ge=60, le=3600, description="Cooldown between scaling operations")

    def validate_vm_host_references(self) -> None:
        """Validate that all VMs reference existing hosts."""
        host_names = {host.name for host in self.proxmox_hosts}
        for vm in self.virtual_machines:
            if vm.proxmox_host not in host_names:
                raise ValueError(f"VM {vm.vm_id} references non-existent host: {vm.proxmox_host}")

    def validate_host_credentials(self) -> None:
        """Validate that all hosts have valid credentials."""
        for host in self.proxmox_hosts:
            host.validate_credentials()

    def model_post_init(self, __context) -> None:
        """Post-initialization validation."""
        self.validate_vm_host_references()
        self.validate_host_credentials()