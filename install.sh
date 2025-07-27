#!/bin/bash
# Install script for Proxmox VM Autoscale - Security-Enhanced Version
# Repository: https://github.com/MatrixMagician/proxmox-vm-autoscale

set -euo pipefail  # Enable strict error handling

# Variables
INSTALL_DIR="/usr/local/bin/vm_autoscale"
CONFIG_DIR="/etc/vm-autoscale"
DATA_DIR="/var/lib/vm-autoscale"
LOG_DIR="/var/log/vm-autoscale"
REPO_URL="https://github.com/MatrixMagician/proxmox-vm-autoscale"
SERVICE_FILE="vm_autoscale.service"
SECURE_CONFIG_FILE="$CONFIG_DIR/config.yaml"
ENV_FILE="$CONFIG_DIR/.env"
BACKUP_FILE="$CONFIG_DIR/config.yaml.backup"
REQUIREMENTS_FILE="$INSTALL_DIR/requirements.txt"
PYTHON_CMD="/usr/bin/python3"
VM_USER="vm-autoscale"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "Please run this script as root (use sudo)"
    fi
}

# Check system requirements
check_requirements() {
    log_step "Checking system requirements..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        error_exit "Python 3 is required but not installed"
    fi
    
    # Check Python version (requires 3.8+)
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        error_exit "Python 3.8 or higher is required (found: $python_version)"
    fi
    
    log_info "Python version: $python_version ✓"
    
    # Check for required commands
    for cmd in git systemctl; do
        if ! command -v "$cmd" &> /dev/null; then
            error_exit "$cmd is required but not installed"
        fi
    done
    
    log_info "System requirements check passed ✓"
}

# Create system user
create_system_user() {
    log_step "Creating system user..."
    
    if id "$VM_USER" &>/dev/null; then
        log_info "User '$VM_USER' already exists ✓"
    else
        useradd -r -s /bin/false -d "$DATA_DIR" -c "VM Autoscale Service" "$VM_USER" || error_exit "Failed to create user $VM_USER"
        log_info "Created system user '$VM_USER' ✓"
    fi
}

# Create directory structure
create_directories() {
    log_step "Creating secure directory structure..."
    
    # Create directories
    for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$DATA_DIR/.ssh"; do
        mkdir -p "$dir" || error_exit "Failed to create directory $dir"
    done
    
    # Set ownership and permissions
    chown root:root "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    chown root:"$VM_USER" "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    chown "$VM_USER":"$VM_USER" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    
    chown "$VM_USER":"$VM_USER" "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    
    chown "$VM_USER":"$VM_USER" "$DATA_DIR/.ssh"
    chmod 700 "$DATA_DIR/.ssh"
    
    # Create known_hosts file
    touch "$DATA_DIR/.ssh/known_hosts"
    chown "$VM_USER":"$VM_USER" "$DATA_DIR/.ssh/known_hosts"
    chmod 644 "$DATA_DIR/.ssh/known_hosts"
    
    log_info "Directory structure created with secure permissions ✓"
}

# Backup existing configuration
backup_config() {
    if [ -f "$SECURE_CONFIG_FILE" ]; then
        log_step "Backing up existing configuration..."
        cp "$SECURE_CONFIG_FILE" "$BACKUP_FILE" || error_exit "Failed to backup configuration"
        log_info "Configuration backed up to $BACKUP_FILE ✓"
    fi
}

# Install system dependencies
install_system_dependencies() {
    log_step "Installing system dependencies..."
    
    # Update package lists
    apt-get update || error_exit "Failed to update package lists"
    
    # Install required packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        git \
        curl \
        build-essential \
        libffi-dev \
        libssl-dev \
        || error_exit "Failed to install system dependencies"
    
    log_info "System dependencies installed ✓"
}

# Clone repository
clone_repository() {
    log_step "Cloning repository..."
    
    if [ -d "$INSTALL_DIR" ]; then
        log_warn "Removing existing installation directory..."
        rm -rf "$INSTALL_DIR" || error_exit "Failed to remove existing directory"
    fi
    
    git clone "$REPO_URL" "$INSTALL_DIR" || error_exit "Failed to clone repository"
    log_info "Repository cloned successfully ✓"
}

# Setup Python virtual environment
setup_python_environment() {
    log_step "Setting up Python virtual environment..."
    
    local venv_dir="$INSTALL_DIR/venv"
    
    # Create virtual environment
    python3 -m venv "$venv_dir" || error_exit "Failed to create virtual environment"
    
    # Upgrade pip
    "$venv_dir/bin/pip" install --upgrade pip || error_exit "Failed to upgrade pip"
    
    # Install dependencies
    if [ -f "$REQUIREMENTS_FILE" ]; then
        "$venv_dir/bin/pip" install -r "$REQUIREMENTS_FILE" || error_exit "Failed to install Python dependencies"
        log_info "Python dependencies installed ✓"
    else
        log_warn "Requirements file not found, installing basic dependencies..."
        "$venv_dir/bin/pip" install \
            "paramiko>=3.4.0" \
            "requests>=2.31.0" \
            "PyYAML>=6.0.1" \
            "cryptography>=41.0.0" \
            "pydantic>=2.5.0" \
            "python-dotenv>=1.0.0" \
            || error_exit "Failed to install basic dependencies"
    fi
    
    # Set permissions
    chown -R "$VM_USER":"$VM_USER" "$venv_dir"
    
    log_info "Python environment setup complete ✓"
}

# Copy configuration files
setup_configuration() {
    log_step "Setting up configuration files..."
    
    # Copy configuration template
    if [ -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.yaml" "$SECURE_CONFIG_FILE" || error_exit "Failed to copy configuration template"
        chown root:"$VM_USER" "$SECURE_CONFIG_FILE"
        chmod 640 "$SECURE_CONFIG_FILE"
        log_info "Configuration template copied ✓"
    else
        log_warn "Secure configuration template not found"
    fi
    
    # Copy environment template
    if [ -f "$INSTALL_DIR/.env.template" ]; then
        cp "$INSTALL_DIR/.env.template" "$CONFIG_DIR/.env.template" || error_exit "Failed to copy environment template"
        chown root:"$VM_USER" "$CONFIG_DIR/.env.template"
        chmod 640 "$CONFIG_DIR/.env.template"
        log_info "Environment template copied ✓"
    fi
    
    # Create secure .env file
    if [ ! -f "$ENV_FILE" ]; then
        touch "$ENV_FILE"
        chown root:"$VM_USER" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        log_info "Secure .env file created ✓"
    fi
    
    # Restore backup if it exists
    if [ -f "$BACKUP_FILE" ]; then
        log_step "Restoring configuration from backup..."
        cp "$BACKUP_FILE" "$SECURE_CONFIG_FILE" || error_exit "Failed to restore configuration backup"
        log_info "Configuration restored from backup ✓"
    fi
}

# Create systemd service
create_systemd_service() {
    log_step "Creating systemd service..."
    
    cat <<EOF > "/etc/systemd/system/$SERVICE_FILE"
[Unit]
Description=Proxmox VM Autoscaler (Secure)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$VM_USER
Group=$VM_USER
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/autoscale.py --config $SECURE_CONFIG_FILE --env-file $ENV_FILE
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vm-autoscale

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $DATA_DIR
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
EOF

    chmod 644 "/etc/systemd/system/$SERVICE_FILE" || error_exit "Failed to set service file permissions"
    log_info "Systemd service created with security hardening ✓"
}

# Setup log rotation
setup_log_rotation() {
    log_step "Setting up log rotation..."
    
    cat <<EOF > "/etc/logrotate.d/vm-autoscale"
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $VM_USER $VM_USER
}
EOF

    chmod 644 "/etc/logrotate.d/vm-autoscale" || error_exit "Failed to create logrotate configuration"
    log_info "Log rotation configured ✓"
}

# Enable service
enable_service() {
    log_step "Enabling systemd service..."
    
    systemctl daemon-reload || error_exit "Failed to reload systemd"
    systemctl enable "$SERVICE_FILE" || error_exit "Failed to enable service"
    
    log_info "Service enabled successfully ✓"
}

# Validate installation
validate_installation() {
    log_step "Validating installation..."
    
    # Test configuration
    if sudo -u "$VM_USER" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/autoscale.py" \
        --config "$SECURE_CONFIG_FILE" \
        --env-file "$ENV_FILE" \
        --validate-only 2>/dev/null; then
        log_info "Configuration validation passed ✓"
    else
        log_warn "Configuration validation failed - please check configuration files"
    fi
}

# Display post-installation instructions
show_instructions() {
    echo
    log_info "=============================================="
    log_info "  Proxmox VM Autoscale Installation Complete"
    log_info "=============================================="
    echo
    log_info "🔧 Next Steps:"
    echo
    log_info "1. Configure your Proxmox hosts and VMs:"
    echo "   sudo nano $SECURE_CONFIG_FILE"
    echo
    log_info "2. Set up your credentials securely:"
    echo "   sudo nano $ENV_FILE"
    echo "   (Use the template: $CONFIG_DIR/.env.template)"
    echo
    log_info "3. Add Proxmox host SSH keys (prevents MITM attacks):"
    echo "   sudo -u $VM_USER ssh-keyscan -H your_proxmox_host >> $DATA_DIR/.ssh/known_hosts"
    echo
    log_info "4. Test configuration:"
    echo "   sudo -u $VM_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/autoscale.py --config $SECURE_CONFIG_FILE --env-file $ENV_FILE --validate-only"
    echo
    log_info "5. Start the service:"
    echo "   sudo systemctl start $SERVICE_FILE"
    echo
    log_info "📊 Monitoring:"
    echo "   Status: sudo systemctl status $SERVICE_FILE"
    echo "   Logs:   sudo journalctl -u $SERVICE_FILE -f"
    echo
    log_info "🔒 Security Notes:"
    echo "   • Service runs as dedicated user '$VM_USER'"
    echo "   • Configuration files have restrictive permissions"
    echo "   • SSH host key verification is enforced"
    echo "   • Systemd security hardening is enabled"
    echo
    if [ -f "$BACKUP_FILE" ]; then
        log_info "📋 Configuration backup: $BACKUP_FILE"
    fi
    echo
    log_info "For detailed documentation, see: $INSTALL_DIR/README.md"
}

# Main installation function
main() {
    log_info "Starting Proxmox VM Autoscale (Secure) Installation..."
    echo
    
    check_root
    check_requirements
    create_system_user
    create_directories
    backup_config
    install_system_dependencies
    clone_repository
    setup_python_environment
    setup_configuration
    create_systemd_service
    setup_log_rotation
    enable_service
    validate_installation
    
    echo
    show_instructions
}

# Run main function
main "$@"