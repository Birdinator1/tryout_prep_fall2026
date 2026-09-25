# Logs

## Linux Logs

* Linux logs are usually somewhere in `/var/log/`

* Syslog is common, either `/var/log/syslog` or `/var/log/messages`. This would be cron logs or iptables logs type things

* Linux authentication logs can be found at `/var/log/auth.log` (Debian) or `/var/log/secure`

* `sudo apt install auditd` Auditd is a logging tool that we can use to create custom logging criteria.

* Services will usually make a folder inside of `/var/log` like `/var/log/apache2/`

## Windows Logs

* Mostly `Windows Event Log`

* **Event Viewer Codes**: [Windows Codes](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

* SYSMON: if you want to use it, you'll have to download the [executable from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). and run it while supplying a config file. There's a config file called [SwiftOnSecurityLinks](https://github.com/SwiftOnSecurity/sysmon-config) with great defaults that you can use. To use Sysmon with it, just download the Sysmon EXE and SwiftOnSecurity XML files linked above and run:

    `sysmon.exe -accepteula -i sysmonconfig-export.xml`
