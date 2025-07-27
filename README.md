# 🚀 Proxmox VM Autoscale - Secure & Modernized

## 🌟 Overview
**Proxmox VM Autoscale** is a dynamic scaling service that automatically adjusts virtual machine (VM) resources (CPU cores and RAM) on your Proxmox Virtual Environment (VE) based on real-time metrics and user-defined thresholds. This solution helps ensure efficient resource usage, optimizing performance and resource availability dynamically.
This project was originally created by Fabrizio Salmi

The service supports multiple Proxmox hosts via SSH connections and can be easily installed and managed as a **systemd** service for seamless automation.

> [!IMPORTANT]
> **🔒 SECURITY-ENHANCED VERSION AVAILABLE**
> 
> This repository now includes a **completely refactored, security-enhanced version** that addresses critical vulnerabilities and follows modern Python design principles. See the [Security Features](#-security-features) section below.

> [!IMPORTANT]
> To enable scaling of VM resources, make sure NUMA and hotplug features are enabled:
> - **Enable NUMA**: VM > Hardware > Processors > Enable NUMA ☑️
> - **Enable CPU Hotplug**: VM > Options > Hotplug > CPU ☑️
> - **Enable Memory Hotplug**: VM > Options > Hotplug > Memory ☑️

## ✨ Features
- 🔄 **Auto-scaling of VM CPU and RAM** based on real-time resource metrics
- 🛡️ **Security-hardened** with injection protection and credential security
- 🛠️ **Configuration-driven** setup using validated YAML configuration
- 🌐 **Multi-host support** via secure SSH (key-based authentication recommended)
- 📲 **Enhanced notifications** (Gotify & Email) with rate limiting
- ⚙️ **Systemd integration** with security hardening features
- 🔍 **Comprehensive logging** with rotation and monitoring
- 🧪 **Configuration validation** with detailed error reporting

---

## 🛡️ Security Features

### 🚨 **Critical Security Fixes**
This refactored version addresses **multiple critical security vulnerabilities** found in the original codebase:

#### ✅ **Command Injection Protection**
- **Before**: `f"qm status {vm_id}"` - vulnerable to injection attacks
- **After**: `execute_command_safe("qm", "status", vm_id)` - parameterized execution
- **Impact**: Prevents arbitrary command execution on Proxmox hosts

#### ✅ **Secure Credential Management**
- **Before**: Plaintext passwords stored in YAML files
- **After**: Environment variables with `${VAR_NAME}` syntax
- **Impact**: Eliminates credential exposure in configuration files

#### ✅ **SSH Security Hardening**
- **Before**: `AutoAddPolicy()` - accepts any host key (MITM vulnerable)
- **After**: Strict host key verification with known_hosts file
- **Impact**: Prevents man-in-the-middle attacks

#### ✅ **Input Validation & Sanitization**
- **Before**: No validation of VM IDs, resource values, or inputs
- **After**: Comprehensive validation using Pydantic models
- **Impact**: Prevents injection attacks and data corruption

#### ✅ **Enhanced Error Handling**
- **Before**: Detailed error messages could leak sensitive information
- **After**: Sanitized error messages with security considerations
- **Impact**: Prevents information disclosure through error messages

### 🔒 **System-Level Security**
- Dedicated system user (`vm-autoscale`) with minimal privileges
- Systemd hardening (NoNewPrivileges, ProtectSystem, etc.)
- Restrictive file permissions (600 for .env, 640 for config)
- Log rotation with proper ownership and access controls

---

## 🚀 Quick Start

### **🔒 Secure Installation (Recommended)**

For the security-enhanced version with automated setup:

```bash
# Clone the repository
git clone https://github.com/MatrixMagician/proxmox-vm-autoscale.git
cd proxmox-vm-autoscale

# Run secure automated setup
sudo python3 setup_secure.py
```

**This secure installation will:**
- Create dedicated `vm-autoscale` system user
- Set up secure directory structure with proper permissions
- Install Python dependencies in isolated virtual environment
- Configure systemd service with security hardening
- Set up log rotation and SSH security

### **⚙️ Configure Environment Variables**
```bash
# Edit the secure environment file
sudo nano /etc/vm-autoscale/.env
```

Example `.env` file:
```bash
# SSH Credentials (use strong passwords or SSH keys)
PROXMOX_HOST1_SSH_PASSWORD=your_secure_password
PROXMOX_HOST2_SSH_PASSWORD=another_secure_password

# Email Configuration
SMTP_PASSWORD=your_smtp_password

# Gotify Configuration  
GOTIFY_APP_TOKEN=your_gotify_token
```

### **🔧 Configure Hosts and VMs**
```bash
# Edit the main configuration
sudo nano /etc/vm-autoscale/config.yaml
```

### **🔑 Set Up SSH Host Keys**
```bash
# Add your Proxmox host keys (prevents MITM attacks)
sudo -u vm-autoscale ssh-keyscan -H your_proxmox_host >> /var/lib/vm-autoscale/.ssh/known_hosts
```

### **✅ Test Configuration**
```bash
# Validate configuration before deployment
sudo -u vm-autoscale python3 /usr/local/bin/vm_autoscale/autoscale_secure.py \
  --config /etc/vm-autoscale/config.yaml \
  --env-file /etc/vm-autoscale/.env \
  --validate-only
```

### **🚀 Start Service**
```bash
# Enable and start the secure service
sudo systemctl enable vm-autoscale-secure.service
sudo systemctl start vm-autoscale-secure.service

# Check status
sudo systemctl status vm-autoscale-secure.service
```

---

## 📋 Prerequisites
- 🖥️ **Proxmox VE** installed on target hosts
- 🐍 **Python 3.8+** (3.12+ recommended for latest security features)
- 🔑 **SSH access** to Proxmox hosts (key-based authentication recommended)
- 🛡️ **Root access** for secure system installation
- 💻 Familiarity with Proxmox `qm` commands and SSH

---

## ⚙️ Configuration

### **🔒 Secure Configuration Format**

The secure version uses environment variables for sensitive data:

```yaml
# Secure configuration with environment variables
scaling_thresholds:
  cpu:
    high: 80    # Scale up when CPU > 80%
    low: 20     # Scale down when CPU < 20%
  ram:
    high: 85    # Scale up when RAM > 85%
    low: 25     # Scale down when RAM < 25%

scaling_limits:
  min_cores: 1      # Minimum CPU cores
  max_cores: 8      # Maximum CPU cores  
  min_ram_mb: 1024  # Minimum RAM (MB)
  max_ram_mb: 16384 # Maximum RAM (MB)

check_interval: 300      # Check every 5 minutes
scale_cooldown: 300      # Cooldown between scaling operations

proxmox_hosts:
  - name: host1
    host: 192.168.1.10
    ssh_user: root
    ssh_password: ${PROXMOX_HOST1_SSH_PASSWORD}  # From environment
    ssh_port: 22
    # ssh_key: /path/to/ssh_key  # Preferred over password

virtual_machines:
  - vm_id: 101
    proxmox_host: host1
    scaling_enabled: true
    cpu_scaling: true
    ram_scaling: true

logging:
  level: INFO
  log_file: /var/log/vm-autoscale/vm_autoscale.log

# Enhanced notifications with security
alerts:
  email_enabled: false
  email_recipient: admin@example.com
  smtp_server: smtp.example.com
  smtp_port: 587
  smtp_user: your_smtp_user
  smtp_password: ${SMTP_PASSWORD}  # From environment

gotify:
  enabled: false
  server_url: https://gotify.example.com
  app_token: ${GOTIFY_APP_TOKEN}   # From environment
  priority: 5

# Host resource limits for safety
host_limits:
  max_host_cpu_percent: 90
  max_host_ram_percent: 90
```

### **📊 Configuration Reference**

#### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PROXMOX_HOST*_SSH_PASSWORD` | SSH password for Proxmox hosts | If not using SSH keys |
| `SMTP_PASSWORD` | SMTP server password | If email alerts enabled |
| `GOTIFY_APP_TOKEN` | Gotify application token | If Gotify enabled |

#### Configuration Validation

The secure version includes comprehensive validation:

- **VM ID Format**: Must be 100-999999
- **Resource Limits**: Validated ranges for CPU/RAM
- **Host Connectivity**: SSH credential validation
- **Email Format**: RFC-compliant email validation
- **URL Validation**: Proper URL format checking

---

## 📊 Monitoring and Logs

### **📜 View Logs**
```bash
# Real-time logs (secure service)
sudo journalctl -u vm-autoscale-secure.service -f

# Log files
sudo tail -f /var/log/vm-autoscale/vm_autoscale.log
```

### **🔍 Check Service Status**
```bash
# Service status
sudo systemctl status vm-autoscale-secure.service

# Configuration validation
sudo -u vm-autoscale python3 /usr/local/bin/vm_autoscale/autoscale_secure.py --validate-only
```

### **📈 Performance Monitoring**
- CPU/RAM usage tracking per VM
- Host resource monitoring
- Scaling operation success/failure rates
- Notification delivery status
- SSH connection health

---

## 🔧 Advanced Configuration

### **🔑 SSH Key-Based Authentication (Recommended)**

1. **Generate SSH key pair:**
```bash
ssh-keygen -t ed25519 -f /var/lib/vm-autoscale/.ssh/id_ed25519
```

2. **Copy public key to Proxmox hosts:**
```bash
ssh-copy-id -i /var/lib/vm-autoscale/.ssh/id_ed25519.pub root@proxmox-host
```

3. **Update configuration:**
```yaml
proxmox_hosts:
  - name: host1
    host: 192.168.1.10
    ssh_user: root
    ssh_key: /var/lib/vm-autoscale/.ssh/id_ed25519
    ssh_port: 22
```

### **🛡️ Security Best Practices**

#### 1. **Credential Security**
- ✅ Use environment variables for all sensitive data
- ✅ Set restrictive file permissions (600 for .env files)
- ✅ Prefer SSH key authentication over passwords
- ✅ Regularly rotate credentials

#### 2. **Network Security**
- ✅ Use SSH host key verification
- ✅ Consider VPN for Proxmox management traffic
- ✅ Limit SSH access to specific IP ranges
- ✅ Use strong SSH keys (Ed25519 recommended)

#### 3. **System Security**
- ✅ Run service as dedicated user (not root)
- ✅ Enable systemd security features
- ✅ Regular security updates
- ✅ Monitor logs for suspicious activity

#### 4. **Operational Security**
- ✅ Regular backup of configurations
- ✅ Monitor service health and performance
- ✅ Implement log rotation and retention
- ✅ Regular security assessments

---

## 🚨 Migration from Original Version

> [!WARNING]
> **CRITICAL SECURITY VULNERABILITIES** in original version:
> 1. **Command Injection** - Arbitrary code execution possible
> 2. **Credential Exposure** - Passwords stored in plaintext
> 3. **SSH MITM** - No host key verification
> 4. **Input Validation** - No validation of user inputs

### **Migration Steps**

#### 1. **Backup Existing Setup**
```bash
cp config.yaml config.yaml.backup
cp autoscale.py autoscale.py.backup
```

#### 2. **Install Secure Version**
```bash
sudo python3 setup_secure.py
```

#### 3. **Migrate Configuration**
- Copy VM and host definitions to new secure format
- Move passwords to environment variables
- Update paths and settings as needed

#### 4. **Security Setup**
```bash
# Set proper file permissions
sudo chmod 600 /etc/vm-autoscale/.env
sudo chmod 640 /etc/vm-autoscale/config.yaml

# Add SSH host keys
sudo -u vm-autoscale ssh-keyscan -H your_host >> /var/lib/vm-autoscale/.ssh/known_hosts
```

#### 5. **Test and Deploy**
```bash
# Test configuration
sudo -u vm-autoscale python3 /usr/local/bin/vm_autoscale/autoscale_secure.py --validate-only

# Start service
sudo systemctl enable vm-autoscale-secure.service
sudo systemctl start vm-autoscale-secure.service
```

---

## 🧪 Development & Testing

### **🔧 Requirements**
```bash
# Install dependencies
pip install paramiko>=3.4.0 requests>=2.31.0 PyYAML>=6.0.1 \
            cryptography>=41.0.0 pydantic>=2.5.0 python-dotenv>=1.0.0
```

### **🐛 Manual Testing**
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Test secure version
python autoscale_secure.py --validate-only --config config_test.yaml --env-file .env.test
```

### **🔍 Debug Mode**
```bash
# Enable debug logging in config.yaml
logging:
  level: DEBUG

# Restart service and monitor logs
sudo systemctl restart vm-autoscale-secure.service
sudo journalctl -u vm-autoscale-secure.service -f
```

---

## 📋 Troubleshooting

### **Common Issues**

#### **SSH Connection Failures**
```bash
# Check host key verification
sudo -u vm-autoscale ssh-keyscan -H your_host >> /var/lib/vm-autoscale/.ssh/known_hosts

# Test SSH connection
sudo -u vm-autoscale ssh user@host
```

#### **Permission Errors**
```bash
# Fix file permissions
sudo chown -R vm-autoscale:vm-autoscale /var/lib/vm-autoscale
sudo chmod 600 /etc/vm-autoscale/.env
sudo chmod 640 /etc/vm-autoscale/config.yaml
```

#### **Configuration Validation Errors**
```bash
# Run validation with detailed output
sudo -u vm-autoscale python3 /usr/local/bin/vm_autoscale/autoscale_secure.py \
  --config /etc/vm-autoscale/config.yaml \
  --env-file /etc/vm-autoscale/.env \
  --validate-only
```

### **Security Alerts**

If you encounter security-related errors:

1. **Host Key Verification Failed**
   - Add the correct host key to known_hosts
   - Verify you're connecting to the correct host

2. **Credential Validation Failed**
   - Check environment variables are set correctly
   - Verify SSH key permissions (600 for private keys)

3. **Input Validation Errors**
   - Check VM IDs are in valid range (100-999999)
   - Verify resource limits are reasonable
   - Ensure all required fields are present

---

## 📊 Performance & Metrics

### **📈 Performance Improvements**

#### **Current Version**
- ✅ **Zero known security vulnerabilities**
- ✅ **Comprehensive input validation**
- ✅ **Efficient connection management**
- ✅ **Smart retry logic with backoff**
- ✅ **Clean, modular architecture**

### **🎯 Efficiency Gains**
- **SSH Connections**: Context manager-based connection handling
- **Resource Monitoring**: Optimized command execution with caching
- **Memory Usage**: Efficient logging with rotation (10MB max, 5 files)
- **Error Recovery**: Exponential backoff and intelligent retry logic
- **Rate Limiting**: Prevents notification spam (60/hour max)

---

## 🏗️ Architecture Overview

### **📁 File Structure**
```
proxmox-vm-autoscale/
├── 🔒 Secure Version (Production)
│   ├── autoscale_secure.py           # Main secure application
│   ├── secure_ssh_client.py          # Injection-proof SSH client
│   ├── secure_config_loader.py       # Secure configuration loader
│   ├── config_models.py              # Pydantic validation models
│   ├── secure_notification_manager.py # Enhanced notifications
│   ├── setup_secure.py               # Automated secure installation
│   ├── config_secure.yaml            # Secure configuration template
│   └── .env.template                 # Environment variables template
├── 📜 Documentation
│   ├── README.md                     # This comprehensive guide
│   └── REFACTORING_SUMMARY.md        # Technical refactoring details
├── 🔧 Utilities
│   ├── requirements.txt              # Python dependencies
│   └── vm_autoscale.service          # Systemd service file
└── 📚 Original Version (Legacy)
    ├── autoscale.py                  # Original application
    ├── vm_manager.py                 # VM resource management
    ├── ssh_utils.py                  # Basic SSH client
    └── host_resource_checker.py      # Host monitoring
```

### **🏛️ Component Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    VM Autoscaler Service                     │
├─────────────────────────────────────────────────────────────┤
│  🔒 Security Layer                                          │
│  • Input validation (Pydantic)                             │
│  • Command injection protection                            │
│  • Credential management                                   │
│  • SSH security hardening                                  │
├─────────────────────────────────────────────────────────────┤
│  🏗️ Application Layer                                       │
│  • Resource monitoring                                     │
│  • Scaling decision engine                                 │
│  • Configuration management                                │
│  • Notification system                                     │
├─────────────────────────────────────────────────────────────┤
│  🔌 Integration Layer                                       │
│  • Secure SSH client                                       │
│  • Proxmox API integration                                 │
│  • External notification services                          │
│  • System logging and monitoring                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤝 Contributing

### Contributors
Code improvements by: **[Specimen67](https://github.com/Specimen67)**, **[brianread108](https://github.com/brianread108)**

---

## 🔗 Related Projects

- [proxmox-lxc-autoscale](https://github.com/MatrixMagician/proxmox-lxc-autoscale) - Automatically scale LXC containers on Proxmox hosts

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details.

## 🎯 Support

For support and questions:
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/MatrixMagician/proxmox-vm-autoscale/issues)
- 💬 **Discussions**: Use GitHub Discussions for general questions
- 📧 **Security Issues**: Report privately to maintainers