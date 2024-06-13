
<h1>Ubuntu/Debian bash hardening script</h1>

<h3>This script performs a comprehensive system hardening process for Ubuntu and Debian operating systems. The steps include documenting host information, securing BIOS, enabling disk encryption, configuring disk partitions, securing SSH, enabling SELinux, setting network parameters, managing password policies, and more. The goal is to enhance the security posture of the system by implementing various best practices and security configurations.</h3>

<h2>           Key features of the provided Ubuntu and Debian hardening script</h2>


<h3>Host Information Documentation:</h3> Captures and logs critical system information such as hostname, kernel version, CPU, memory, and disk details.

<h3>BIOS and Disk Encryption Checks:</h3> Verifies the presence of BIOS protection and disk encryption to ensure they are enabled.

<h3>Disk Partitioning and Mounting:</h3> Sets up essential disk partitions and filesystems, ensuring proper disk usage and management.

<h3>Boot Directory and USB Usage Security:</h3> Secures the boot directory and disables USB storage to prevent unauthorized access.

<h3>System Updates and Installed Package Check:</h3> Ensures the system is up-to-date and lists all installed packages for review.

<h3>SSH Configuration and Security:</h3> Secures SSH by disabling root login, password authentication, and X11 forwarding.

<h3>SELinux Activation:</h3> Installs and activates SELinux to enhance mandatory access control.

<h3>Network and Password Policies:</h3> Configures network parameters and enforces stringent password policies.

<h3>Permissions and Integrity Verifications:</h3> Sets proper permissions on sensitive files and verifies the integrity of installed packages.

<h3>Process and Service Hardening:</h3> Disables core dumps, restricts access to kernel logs, and removes unnecessary services.

<h3>CRON and Root Access Restrictions:</h3> Limits CRON access to root and restricts root privileges using sudo.

<h3>Monitoring and Auditing:</h3> Installs and configures tools like auditd and fail2ban to monitor user activities and prevent unauthorized access.

<h3>Rootkit Detection:</h3> Installs and runs rkhunter to detect rootkits and other security breaches.

<h3>System Log Monitoring:</h3> Installs logwatch to provide detailed monitoring and analysis of system logs.

<h3>Two-Factor Authentication:</h3> Enables 2-factor authentication using Google Authenticator for enhanced security.
