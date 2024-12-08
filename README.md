# 🚀 VM Autoscale

## 🌟 Overview
**Proxmox VM Autoscale** is a dynamic scaling service that automatically adjusts virtual machine (VM) resources (CPU cores and RAM) on your Proxmox Virtual Environment (VE) based on real-time metrics and user-defined thresholds. This solution helps ensure efficient resource usage, optimizing performance and resource availability dynamically.

The service supports multiple Proxmox hosts via SSH connections and can be easily installed and managed as a **systemd** service for seamless automation.

> [!IMPORTANT]
> To enable scaling of VM resources, make sure NUMA and hotplug features are enabled:
> - **Enable NUMA**: VM > Hardware > Processors > Enable NUMA ☑️
> - **Enable CPU Hotplug**: VM > Options > Hotplug > CPU ☑️
> - **Enable Memory Hotplug**: VM > Options > Hotplug > Memory ☑️

## ✨ Features
- 🔄 **Auto-scaling of VM CPU and RAM** based on real-time resource metrics.
- 🛠️ **Configuration-driven** setup using an easy-to-edit YAML file.
- 🌐 **Multi-host support** via SSH (compatible with both password and key-based authentication).
- 📲 **Gotify Notifications** for alerting you whenever scaling actions are performed.
- ⚙️ **Systemd Integration** for effortless setup, management, and monitoring as a Linux service.

## 📋 Prerequisites
- 🖥️ **Proxmox VE** must be installed on the target hosts.
- 🐍 **Python 3.x** should be installed on the Proxmox host(s).
- 💻 Familiarity with Proxmox `qm` commands and SSH is recommended.

> [!NOTE]
> To autoscale LXC containers on Proxmox hosts, you may be interested in [this related project](https://github.com/fabriziosalmi/proxmox-lxc-autoscale).

## 🚀 Quick Start

To install **Proxmox VM Autoscale**, execute the following `curl bash` command. This command will automatically clone the repository, execute the installation script, and set up the service for you:

```bash
bash <(curl -s https://raw.githubusercontent.com/fabriziosalmi/proxmox-vm-autoscale/main/install.sh)
```

🎯 **This installation script will:**
- Clone the repository into `/usr/local/bin/vm_autoscale`.
- Copy all necessary files to the installation directory.
- Install the required Python dependencies.
- Set up a **systemd unit file** to manage the autoscaling service.

> [!NOTE]
> The service is enabled but not started automatically at the end of the installation. To start it manually, use the following command.

```bash
systemctl start vm_autoscale.service
```

> [!IMPORTANT]
> Make sure to review the official [Proxmox documentation](https://pve.proxmox.com/wiki/Hotplug_(qemu_disk,nic,cpu,memory)) for the hotplug feature requirements to enable scaling virtual machines on the fly.

## ⚡ Usage

### ▶️ Start/Stop the Service
To **start** the autoscaling service:

```bash
systemctl start vm_autoscale.service
```

To **stop** the service:

```bash
systemctl stop vm_autoscale.service
```

### 🔍 Check the Status
To view the service status:

```bash
systemctl status vm_autoscale.service
```

### 📜 Logs
Logs are saved to `/var/log/vm_autoscale.log`. You can monitor the logs in real-time using:

```bash
tail -f /var/log/vm_autoscale.log
```

Or by using `journalctl`:

```bash
journalctl -u vm_autoscale.service -f
```

## ⚙️ Configuration

The configuration file (`config.yaml`) is located at `/usr/local/bin/vm_autoscale/config.yaml`. This file contains settings for scaling thresholds, resource limits, Proxmox hosts, and VM information.

### Example Configuration
```yaml
scaling_thresholds:
  cpu:
    high: 80
    low: 20
  ram:
    high: 85
    low: 25

scaling_limits:
  min_cores: 1
  max_cores: 8
  min_ram_mb: 512
  max_ram_mb: 16384

check_interval: 60  # Check every 60 seconds

proxmox_hosts:
  - name: host1
    host: 192.168.1.10
    ssh_user: root
    ssh_password: your_password_here
    ssh_key: /path/to/ssh_key

virtual_machines:
  - vm_id: 101
    proxmox_host: host1
    scaling_enabled: true
    cpu_scaling: true
    ram_scaling: true

logging:
  level: INFO
  log_file: /var/log/vm_autoscale.log

gotify:
  enabled: true
  server_url: https://gotify.example.com
  app_token: your_gotify_app_token_here
  priority: 5
```

### ⚙️ Configuration Details
- **`scaling_thresholds`**: Defines the CPU and RAM usage thresholds that trigger scaling actions (e.g., when CPU > 80%, scale up).
- **`scaling_limits`**: Specifies the **minimum** and **maximum** resources (CPU cores and RAM) each VM can have.
- **`proxmox_hosts`**: Contains the details of Proxmox hosts, including SSH credentials.
- **`virtual_machines`**: Lists the VMs to be managed by the autoscaling script, allowing per-VM scaling customization.
- **`logging`**: Specifies the logging level and log file path for activity tracking and debugging.
- **`gotify`**: Configures **Gotify notifications** to send alerts when scaling actions are performed.

## 📲 Gotify Notifications
Gotify is used to send real-time notifications regarding scaling actions. Configure Gotify in the `config.yaml` file:
- **`enabled`**: Set to `true` to enable notifications.
- **`server_url`**: URL of the Gotify server.
- **`app_token`**: Authentication token for accessing Gotify.
- **`priority`**: Notification priority level (1-10).

## 👨‍💻 Development

### 🔧 Requirements
- **Python 3.x**
- Required Python Packages: `paramiko`, `requests`, `PyYAML`

### 🐛 Running Manually
To run the script manually for debugging or testing:

```bash
python3 /usr/local/bin/vm_autoscale/autoscale.py
```

### 🤝 Contributing
Contributions are **more** than welcome! If you encounter a bug or have suggestions for improvement, please submit an issue or a pull request.

Code improvements by: [Specimen67](https://github.com/Specimen67), [brianread108](https://github.com/brianread108)

### ⚠️ Disclaimer
> [!CAUTION]
> The author assumes no responsibility for any damage or issues that may arise from using this tool.

### 📜 License
This project is licensed under the **MIT License**. See the LICENSE file for complete details.
