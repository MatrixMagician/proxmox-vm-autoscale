#!/usr/bin/env python3
"""
Secure setup script for VM Autoscale with security hardening.
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse
import getpass


def run_command(cmd, check=True, capture_output=False):
    """Run a system command safely."""
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=check)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {cmd}")
        print(f"Error: {e}")
        if capture_output and e.stdout:
            print(f"Stdout: {e.stdout}")
        if capture_output and e.stderr:
            print(f"Stderr: {e.stderr}")
        sys.exit(1)


def check_requirements():
    """Check system requirements."""
    print("Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Check if running as root (for system installation)
    if os.geteuid() != 0:
        print("Warning: Not running as root. Some installation steps may fail.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    print("✓ Requirements check passed")


def create_user_and_group():
    """Create dedicated user and group for the service."""
    print("Creating dedicated user and group...")
    
    try:
        # Check if user already exists
        run_command("id vm-autoscale", capture_output=True)
        print("✓ User 'vm-autoscale' already exists")
    except:
        # Create system user
        run_command("useradd -r -s /bin/false -d /var/lib/vm-autoscale vm-autoscale")
        print("✓ Created user 'vm-autoscale'")


def setup_directories(install_dir="/usr/local/bin/vm_autoscale"):
    """Set up secure directory structure."""
    print(f"Setting up directories in {install_dir}...")
    
    directories = [
        install_dir,
        "/var/lib/vm-autoscale",
        "/var/log/vm-autoscale",
        "/etc/vm-autoscale"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    # Set secure permissions
    run_command(f"chown -R vm-autoscale:vm-autoscale /var/lib/vm-autoscale")
    run_command(f"chown -R vm-autoscale:vm-autoscale /var/log/vm-autoscale")
    run_command(f"chmod 755 {install_dir}")
    run_command(f"chmod 750 /var/lib/vm-autoscale")
    run_command(f"chmod 750 /var/log/vm-autoscale")
    run_command(f"chmod 755 /etc/vm-autoscale")
    
    print("✓ Set secure directory permissions")
    return install_dir


def install_python_dependencies(install_dir):
    """Install Python dependencies in a virtual environment."""
    print("Installing Python dependencies...")
    
    venv_dir = f"{install_dir}/venv"
    
    # Create virtual environment
    run_command(f"python3 -m venv {venv_dir}")
    
    # Upgrade pip
    run_command(f"{venv_dir}/bin/pip install --upgrade pip")
    
    # Install dependencies
    requirements_file = f"{install_dir}/requirements.txt"
    if Path(requirements_file).exists():
        run_command(f"{venv_dir}/bin/pip install -r {requirements_file}")
    else:
        # Install basic dependencies
        dependencies = [
            "paramiko>=3.4.0",
            "requests>=2.31.0",
            "PyYAML>=6.0.1",
            "cryptography>=41.0.0",
            "pydantic>=2.5.0",
            "python-dotenv>=1.0.0"
        ]
        for dep in dependencies:
            run_command(f"{venv_dir}/bin/pip install '{dep}'")
    
    # Set permissions
    run_command(f"chown -R vm-autoscale:vm-autoscale {venv_dir}")
    
    print("✓ Python dependencies installed")


def copy_files(install_dir):
    """Copy application files to installation directory."""
    print("Copying application files...")
    
    current_dir = Path(__file__).parent
    
    # Files to copy
    files_to_copy = [
        "autoscale_secure.py",
        "secure_ssh_client.py",
        "vm_manager.py",
        "host_resource_checker.py",
        "secure_notification_manager.py",
        "secure_config_loader.py",
        "config_models.py",
        "requirements.txt"
    ]
    
    for file_name in files_to_copy:
        src = current_dir / file_name
        dst = Path(install_dir) / file_name
        if src.exists():
            shutil.copy2(src, dst)
            run_command(f"chown vm-autoscale:vm-autoscale {dst}")
            run_command(f"chmod 644 {dst}")
            print(f"✓ Copied {file_name}")
        else:
            print(f"⚠ Warning: {file_name} not found")


def setup_configuration(install_dir):
    """Set up secure configuration files."""
    print("Setting up configuration files...")
    
    config_dir = "/etc/vm-autoscale"
    current_dir = Path(__file__).parent
    
    # Copy configuration template
    config_template = current_dir / "config_secure.yaml"
    config_dest = f"{config_dir}/config.yaml"
    
    if config_template.exists():
        shutil.copy2(config_template, config_dest)
        run_command(f"chown vm-autoscale:vm-autoscale {config_dest}")
        run_command(f"chmod 640 {config_dest}")  # Readable only by owner and group
        print(f"✓ Configuration template copied to {config_dest}")
    
    # Copy environment template
    env_template = current_dir / ".env.template"
    env_dest = f"{config_dir}/.env.template"
    
    if env_template.exists():
        shutil.copy2(env_template, env_dest)
        run_command(f"chown vm-autoscale:vm-autoscale {env_dest}")
        run_command(f"chmod 640 {env_dest}")
        print(f"✓ Environment template copied to {env_dest}")
    
    # Create actual .env file if it doesn't exist
    env_file = f"{config_dir}/.env"
    if not Path(env_file).exists():
        Path(env_file).touch()
        run_command(f"chown vm-autoscale:vm-autoscale {env_file}")
        run_command(f"chmod 600 {env_file}")  # Only readable by owner
        print(f"✓ Created secure .env file at {env_file}")
        print(f"⚠ Please edit {env_file} with your actual credentials")


def create_systemd_service(install_dir):
    """Create systemd service file."""
    print("Creating systemd service...")
    
    service_content = f"""[Unit]
Description=Proxmox VM Autoscaler (Secure)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vm-autoscale
Group=vm-autoscale
ExecStart={install_dir}/venv/bin/python {install_dir}/autoscale_secure.py --config /etc/vm-autoscale/config.yaml --env-file /etc/vm-autoscale/.env
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vm-autoscale

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/vm-autoscale /var/lib/vm-autoscale
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
"""
    
    service_file = "/etc/systemd/system/vm-autoscale-secure.service"
    with open(service_file, 'w') as f:
        f.write(service_content)
    
    run_command(f"chmod 644 {service_file}")
    run_command("systemctl daemon-reload")
    
    print(f"✓ Systemd service created: {service_file}")


def setup_logrotate():
    """Set up log rotation."""
    print("Setting up log rotation...")
    
    logrotate_content = """/var/log/vm-autoscale/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su vm-autoscale vm-autoscale
}
"""
    
    logrotate_file = "/etc/logrotate.d/vm-autoscale"
    with open(logrotate_file, 'w') as f:
        f.write(logrotate_content)
    
    run_command(f"chmod 644 {logrotate_file}")
    print(f"✓ Log rotation configured: {logrotate_file}")


def setup_ssh_security():
    """Set up SSH security configuration."""
    print("Setting up SSH security...")
    
    ssh_dir = "/var/lib/vm-autoscale/.ssh"
    Path(ssh_dir).mkdir(parents=True, exist_ok=True)
    
    # Create known_hosts file
    known_hosts = f"{ssh_dir}/known_hosts"
    Path(known_hosts).touch()
    
    # Set permissions
    run_command(f"chown -R vm-autoscale:vm-autoscale {ssh_dir}")
    run_command(f"chmod 700 {ssh_dir}")
    run_command(f"chmod 644 {known_hosts}")
    
    print(f"✓ SSH directory created: {ssh_dir}")
    print(f"⚠ Please add your Proxmox host keys to {known_hosts}")
    print("   You can use: ssh-keyscan -H your_proxmox_host >> {known_hosts}")


def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="Secure VM Autoscale Setup")
    parser.add_argument(
        "--install-dir",
        default="/usr/local/bin/vm_autoscale",
        help="Installation directory"
    )
    parser.add_argument(
        "--skip-dependencies",
        action="store_true",
        help="Skip Python dependency installation"
    )
    
    args = parser.parse_args()
    
    print("=== Secure VM Autoscale Setup ===")
    print()
    
    try:
        check_requirements()
        create_user_and_group()
        install_dir = setup_directories(args.install_dir)
        copy_files(install_dir)
        
        if not args.skip_dependencies:
            install_python_dependencies(install_dir)
        
        setup_configuration(install_dir)
        create_systemd_service(install_dir)
        setup_logrotate()
        setup_ssh_security()
        
        print()
        print("=== Setup Complete ===")
        print()
        print("Next steps:")
        print("1. Edit /etc/vm-autoscale/config.yaml with your Proxmox hosts and VMs")
        print("2. Edit /etc/vm-autoscale/.env with your credentials")
        print("3. Add Proxmox host keys to /var/lib/vm-autoscale/.ssh/known_hosts")
        print("4. Test configuration: sudo -u vm-autoscale python3 /usr/local/bin/vm_autoscale/autoscale_secure.py --config /etc/vm-autoscale/config.yaml --env-file /etc/vm-autoscale/.env --validate-only")
        print("5. Enable and start service: systemctl enable vm-autoscale-secure.service && systemctl start vm-autoscale-secure.service")
        print()
        print("Security notes:")
        print("- Configuration files have restrictive permissions")
        print("- Service runs as dedicated user 'vm-autoscale'")
        print("- Sensitive data should be stored in environment variables")
        print("- SSH host key verification is enforced")
        
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nSetup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()