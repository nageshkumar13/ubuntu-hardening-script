#!/bin/bash

#######################################
# Hardening script for Ubuntu and Debian 
#######################################

# Step 1: Document the host information
echo -e "\e[33mStep 1: Documenting host information\e[0m"
echo "Hostname: $(hostname)"  # Print the hostname of the system
echo "Kernel version: $(uname -r)"  # Print the kernel version
echo "Distribution: $(lsb_release -d | cut -f2)"  # Print the distribution description
echo "CPU information: $(lscpu | grep 'Model name')"  # Print CPU model name
echo "Memory information: $(free -h | awk '/Mem/{print $2}')"  # Print total memory
echo "Disk information: $(lsblk | grep disk)"  # Print disk information
echo 

# Step 2: BIOS protection
echo -e "\e[33mStep 2: BIOS protection\e[0m"
echo "Checking if BIOS protection is enabled..."
if [ -f /sys/devices/system/cpu/microcode/reload ]; then
  echo "BIOS protection is enabled"  # Confirm if BIOS protection is enabled
else
  echo "BIOS protection is not enabled"  # Indicate BIOS protection is not enabled
fi
echo ""

# Step 3: Hard disk encryption
echo -e "\e[33mStep 3: Hard disk encryption\e[0m"
echo "Checking if hard disk encryption is enabled..."
if [ -d /etc/luks ]; then
  echo "Hard disk encryption is enabled"  # Confirm if disk encryption is enabled
else
  echo "Hard disk encryption is not enabled"  # Indicate disk encryption is not enabled
fi
echo ""

# Step 4: Disk partitioning
echo -e "\e[33mStep 4: Disk partitioning\e[0m"
echo "Checking if disk partitioning is already done..."
if [ -d /home -a -d /var -a -d /usr ]; then
  echo "Disk partitioning is already done"  # Confirm if disk partitioning is done
else
  echo "Disk partitioning is not done or incomplete"  # Indicate disk partitioning is not done
fi
sudo fdisk /dev/sda  # Open fdisk to manage disk partitions on /dev/sda
sudo mkfs.ext4 /dev/sda1  # Create an ext4 filesystem on /dev/sda1
sudo mkswap /dev/sda2  # Create a swap area on /dev/sda2
sudo swapon /dev/sda2  # Enable the swap area on /dev/sda2
sudo mount /dev/sda1 /mnt  # Mount /dev/sda1 to /mnt
echo

# Step 5: Lock the boot directory
echo -e "\e[33mStep 5: Lock the boot directory\e[0m"
echo "Locking the boot directory..."
sudo chmod 700 /boot  # Restrict access to the boot directory
echo ""

# Step 6: Disable USB usage
echo -e "\e[33mStep 6: Disable USB usage\e[0m"
echo "Disabling USB usage..."
echo 'blacklist usb-storage' | sudo tee /etc/modprobe.d/blacklist-usbstorage.conf  # Disable USB storage
echo ""

# Step 7: Update your system
echo -e "\e[33mStep 7: Updating your system\e[0m"
sudo apt-get update && sudo apt-get upgrade -y  # Update and upgrade system packages
echo ""

# Step 8: Check the installed packages
echo -e "\e[33mStep 8: Checking the installed packages\e[0m"
dpkg --get-selections | grep -v deinstall  # List all installed packages
echo ""

# Step 9: Check for open ports
echo -e "\e[33mStep 9: Checking for open ports\e[0m"
sudo netstat -tulpn  # Display open ports and their associated processes
echo ""

# Step 10: Secure SSH
echo -e "\e[33mStep 10: Securing SSH\e[0m"
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config  # Disable root login over SSH
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config  # Disable password authentication
sudo systemctl restart sshd  # Restart SSH service
echo

# Step 11: Enable SELinux
echo -e "\e[33mStep 11: Enabling SELinux\e[0m"
echo "Checking if SELinux is installed..."
if [ -f /etc/selinux/config ]; then
  echo "SELinux is already installed"  # Confirm if SELinux is installed
else
  echo "SELinux is not installed, installing now..."
  sudo apt-get install selinux-utils selinux-basics -y  # Install SELinux packages
fi
echo "Enabling SELinux..."
sudo selinux-activate  # Activate SELinux
echo ""

# Step 12: Set network parameters
echo -e "\e[33mStep 12: Setting network parameters\e[0m"
echo "Setting network parameters..."
sudo sysctl -p  # Apply network parameter changes
echo ""

# Step 13: Manage password policies
echo -e "\e[33mStep 13: Managing password policies\e[0m"
echo "Modifying the password policies..."
sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/g' /etc/login.defs  # Set maximum password age to 90 days
sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/g' /etc/login.defs  # Set minimum password age to 7 days
sudo sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/g' /etc/login.defs  # Set password expiration warning to 14 days
echo ""

# Step 14: Permissions and verifications
echo -e "\e[33mStep 14: Permissions and verifications\e[0m"
echo "Setting the correct permissions on sensitive files..."
sudo chmod 700 /etc/shadow /etc/gshadow /etc/passwd /etc/group  # Restrict permissions on sensitive files
sudo chmod 600 /boot/grub/grub.cfg  # Restrict permissions on GRUB configuration
sudo chmod 644 /etc/fstab /etc/hosts /etc/hostname /etc/timezone /etc/bash.bashrc  # Set correct permissions on configuration files
echo "Verifying the integrity of system files..."
sudo debsums -c  # Check integrity of installed packages
echo ""

# Step 15: Additional distro process hardening
echo -e "\e[33mStep 15: Additional distro process hardening\e[0m"
echo "Disabling core dumps..."
sudo echo '* hard core 0' | sudo tee /etc/security/limits.d/core.conf  # Disable core dumps
echo "Restricting access to kernel logs..."
sudo chmod 640 /var/log/kern.log  # Restrict access to kernel logs
echo "Setting the correct permissions on init scripts..."
sudo chmod 700 /etc/init.d/*  # Restrict permissions on init scripts
echo ""

# Step 16: Remove unnecessary services
echo -e "\e[33mStep 16: Removing unnecessary services\e[0m"
echo "Removing unnecessary services..."
sudo apt-get purge rpcbind rpcbind-* -y  # Remove RPC bind services
sudo apt-get purge nis -y  # Remove NIS services
echo ""

# Step 17: Check for security on key files
echo -e "\e[33mStep 17: Checking for security on key files\e[0m"
echo "Checking for security on key files..."
sudo find /etc/ssh -type f -name 'ssh_host_*_key' -exec chmod 600 {} \;  # Set correct permissions on SSH host keys
echo ""

# Step 18: Limit root access using SUDO
echo -e "\e[33mStep 18: Limiting root access using SUDO\e[0m"
echo "Limiting root access using SUDO..."
sudo apt-get install sudo -y  # Ensure sudo is installed
sudo groupadd admin  # Create an admin group
sudo usermod -aG admin $USER  # Add current user to admin group
sudo sed -i 's/%sudo\tALL=(ALL:ALL) ALL/%admin\tALL=(ALL:ALL) ALL/g' /etc/sudoers  # Update sudoers file to use admin group
echo ""

# Step 19: Only allow root to access CRON
echo -e "\e[33mStep 19: Restricting access to CRON\e[0m"
echo "Only allowing root to access CRON..."
sudo chmod 600 /etc/crontab  # Restrict permissions on crontab
sudo chown root:root /etc/crontab  # Set ownership of crontab to root
sudo chmod 600 /etc/cron.hourly/*  # Restrict permissions on cron.hourly jobs
sudo chmod 600 /etc/cron.daily/*  # Restrict permissions on cron.daily jobs
sudo chmod 600 /etc/cron.weekly/*  # Restrict permissions on cron.weekly jobs
sudo chmod 600 /etc/cron.monthly/*  # Restrict permissions on cron.monthly jobs
sudo chmod 600 /etc/cron.d/*  # Restrict permissions on cron.d jobs
echo ""

# Step 20: Remote access and SSH basic settings
echo -e "\e[33mStep 20: Remote access and SSH basic settings\e[0m"
echo "Disabling root login over SSH..."
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config  # Disable root login over SSH
echo "Disabling password authentication over SSH..."
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config  # Disable password authentication over SSH
echo "Disabling X11 forwarding over SSH..."
sudo sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config  # Disable X11 forwarding over SSH
echo "Reloading the SSH service..."
sudo systemctl reload sshd  # Reload SSH service to apply changes
echo ""

# Step 21: Disable Xwindow
echo -e "\e[33mStep 21: Disabling Xwindow\e[0m"
echo "Disabling Xwindow..."
sudo systemctl set-default multi-user.target  # Set default system target to multi-user (no GUI)
echo ""

# Step 22: Minimize Package Installation
echo -e "\e[33mStep 22: Minimizing Package Installation\e[0m"
echo "Installing only essential packages..."
sudo apt-get install --no-install-recommends -y systemd-sysv apt-utils  # Install only essential packages
sudo apt-get --purge autoremove -y  # Remove unnecessary packages
echo ""

# Step 23: Checking accounts for empty passwords
echo -e "\e[33mStep 23: Checking accounts for empty passwords\e[0m"
echo "Checking for accounts with empty passwords..."
sudo awk -F: '($2 == "" ) {print}' /etc/shadow  # Check for accounts with empty passwords
echo ""

# Step 24: Monitor user activities
echo -e "\e[33mStep 24: Monitoring user activities\e[0m"
echo "Installing auditd for user activity monitoring..."
sudo apt-get install auditd -y  # Install auditd
echo "Configuring auditd..."
sudo echo "-w /var/log/auth.log -p wa -k authentication" | sudo tee -a /etc/audit/rules.d/audit.rules  # Monitor authentication log
sudo echo "-w /etc/passwd -p wa -k password-file" | sudo tee -a /etc/audit/rules.d/audit.rules  # Monitor passwd file
sudo echo "-w /etc/group -p wa -k group-file" | sudo tee -a /etc/audit/rules.d/audit.rules  # Monitor group file
sudo systemctl restart auditd  # Restart auditd service
echo ""

# Step 25: Install and configure fail2ban
echo -e "\e[33mStep 25: Installing and configuring fail2ban\e[0m"
echo "Installing fail2ban..."
sudo apt-get install fail2ban -y  # Install fail2ban
echo "Configuring fail2ban..."
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local  # Copy default configuration to jail.local
sudo sed -i 's/bantime  = 10m/bantime  = 1h/g' /etc/fail2ban/jail.local  # Set ban time to 1 hour
sudo sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local  # Set max retry attempts to 3
sudo systemctl enable fail2ban  # Enable fail2ban service
sudo systemctl start fail2ban  # Start fail2ban service
echo ""

# Step 26: Rootkit detection
echo -e "\e[33mStep 26: Installing and running Rootkit detection...\e[0m"
sudo apt-get install rkhunter  # Install rkhunter for rootkit detection
sudo rkhunter --update  # Update rkhunter database
sudo rkhunter --propupd  # Update rkhunter properties
sudo rkhunter --check  # Run rkhunter check
echo

# Step 27: Monitor system logs
echo -e "\e[33mStep 27: Monitoring system logs\e[0m"
echo "Installing logwatch for system log monitoring..."
sudo apt-get install logwatch -y  # Install logwatch for monitoring system logs
echo ""

# Step 28: Enable 2-factor authentication
echo -e "\e[33mStep 28: Enabling 2-factor authentication\e[0m"
echo "Installing Google Authenticator for 2-factor authentication..."
sudo apt-get install libpam-google-authenticator -y  # Install Google Authenticator PAM module
echo "Enabling 2-factor authentication..."
sudo google-authenticator  # Configure Google Authenticator for 2FA
echo "Editing PAM settings for 2-factor authentication..."
sudo sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config  # Enable challenge-response authentication
sudo sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config  # Enable PAM usage
sudo sed -i 's/#auth required pam_google_authenticator.so/auth required pam_google_authenticator.so/g' /etc/pam.d/sshd  # Enable Google Authenticator in PAM settings
sudo systemctl reload sshd  # Reload SSH service
echo ""

echo -e "\e[32mHardening complete!\e[0m"  # Indicate that the hardening process is complete
