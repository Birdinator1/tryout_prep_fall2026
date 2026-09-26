# Splunk

## Terms

* Indexer: how you look through the logs

* Forwarders: send logs to indexer

## Setting up the Indexer

To setup the indexer, you'll need to:

1. Enable listening on port 9997 - this is how forwarders will send your machine logs (note: you'll also need to make sure port 9997 TCP is allowed through your host firewall)

2. Add a linux index and a windows index - indices are how Splunk stores data

3. Restart the indexer to apply your changes

``` bash
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk enable listen 9997
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add index linux
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add index windows
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk restart
```

## Configure the Forwarder

To setup the forwarder, you'll need to:

1. Add a forward server - the should be the IP address of the indexer you just set up and port 9997, which you setup a listener on

2. Add monitors - monitors are the files or directories that the forwarder will send to the indexer (hint: you should monitor all of the logs we talked about in the previous module)

3. Restart the forwarder to apply your changes

``` bash
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add forward-server <your indexer ip>:9997
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor /var/log/syslog -index linux
sudo -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk restart
```

## Accessing the Web GUI

Navigate to `http://<your indexer ip>:8000` in your web browser (note: you'll need to make sure TCP port 8000 is allowed through your indexer machine's firewall).

### Common SPL Queries

* index=*

<!-- WINDOWS SPL SECTION -->

## Useful Splunk SPL Queries

## Basic Investigation Queries

### See What Data Is Available

```spl
| tstats count where index=* by index sourcetype host
| sort - count
```

```spl
index=* earliest=-24h@h latest=now
| stats count by index sourcetype host source
| sort - count
```

### Search for a Host, User, IP, or String

```spl
index=* earliest=-24h@h latest=now
("<ip>" OR "<name>" OR "<filename>")
| stats count by index sourcetype host source
```

### View Individual Events

```spl
index=<index> host=<host> earliest=-1h
| table _time host user src_ip dest_ip EventCode action message
| sort 0 - _time
```

### Find the Most Common Values

```spl
index=* earliest=-24h
| top limit=20 user
```

```spl
index=* earliest=-24h
| stats count by host
| sort - count
```

## Windows Authentication

### Failed Logons

```spl
index=<windows_index> EventCode=4625 earliest=-24h
| stats count values(user) as users by src_ip host
| sort - count
```

### Detect Possible Brute-Force Activity

```spl
index=<windows_index> EventCode=4625 earliest=-24h
| bin _time span=5m
| stats count dc(user) as unique_users values(user) as users by _time src_ip
| where count >= 10
| sort - count
```

### Failed Logons Followed by a Successful Logon

```spl
index=<windows_index> (EventCode=4625 OR EventCode=4624) earliest=-24h
| eval result=if(EventCode=4625,"failure","success")
| stats count(eval(result="failure")) as failures
        count(eval(result="success")) as successes
        values(user) as users
        by src_ip
| where failures >= 10 AND successes > 0
| sort - failures
```

### Successful Logons

```spl
index=<windows_index> EventCode=4624 earliest=-24h
| stats count values(Logon_Type) as logon_types by user src_ip host
| sort - count
```

### Remote Desktop Activity

```spl
index=<windows_index> EventCode=4624 Logon_Type=10 earliest=-24h
| table _time user src_ip host
| sort 0 - _time
```

## Account and Privilege Activity

### New User Accounts

```spl
index=<windows_index> EventCode=4720 earliest=-7d
| table _time host SubjectUserName TargetUserName
| sort 0 - _time
```

### Users Added to Privileged Groups

```spl
index=<windows_index> (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-7d
| table _time host SubjectUserName MemberName Group_Name
| sort 0 - _time
```

### Account Modifications

```spl
index=<windows_index> (EventCode=4738 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726)
| table _time host SubjectUserName TargetUserName EventCode
| sort 0 - _time
```

## Processes and PowerShell

### Process Creation

```spl
index=<windows_index> EventCode=4688 earliest=-24h
| table _time host user New_Process_Name Creator_Process_Name CommandLine
| sort 0 - _time
```

### Suspicious PowerShell Commands

```spl
index=<windows_index> (EventCode=4104 OR EventCode=4688) earliest=-24h
| eval command=coalesce(ScriptBlockText, CommandLine, process)
| search command="*EncodedCommand*"
    OR command="*-enc*"
    OR command="*IEX*"
    OR command="*DownloadString*"
    OR command="*FromBase64String*"
| table _time host user command
| sort 0 - _time
```

### Common Suspicious Binaries

```spl
index=<windows_index> EventCode=4688 earliest=-24h
| search New_Process_Name="*\\powershell.exe"
    OR New_Process_Name="*\\certutil.exe"
    OR New_Process_Name="*\\bitsadmin.exe"
    OR New_Process_Name="*\\rundll32.exe"
    OR New_Process_Name="*\\mshta.exe"
    OR New_Process_Name="*\\regsvr32.exe"
    OR New_Process_Name="*\\wmic.exe"
| table _time host user New_Process_Name CommandLine
```

### Services Created

```spl
index=<windows_index> EventCode=7045 earliest=-7d
| table _time host user Service_Name Image_Path Service_File_Name
| sort 0 - _time
```

### Scheduled Tasks Created

```spl
index=<windows_index> EventCode=4698 earliest=-7d
| table _time host user Task_Name Task_Content
| sort 0 - _time
```
<!-- LINUX SPL SECTION -->

## Network and DNS Investigation

### Top Source and Destination Pairs

```spl
index=<network_index> earliest=-24h
| stats count sum(bytes) as total_bytes by src_ip dest_ip dest_port
| sort - total_bytes
```

### Top Outbound Connections

```spl


## Linux Authentication and SSH

### Failed SSH Logons

```spl
index=<linux_index> earliest=-24h
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<src_ip>\S+)"
| rex field=_raw "for (invalid user )?(?<user>\S+)"
| stats count dc(user) as unique_users values(user) as users by src_ip host
| sort - count
```

### Successful SSH Logons

```spl
index=<linux_index> earliest=-24h
("Accepted password" OR "Accepted publickey")
| rex field=_raw "Accepted \S+ for (?<user>\S+) from (?<src_ip>\S+)"
| table _time host user src_ip _raw
| sort 0 - _time
```

### Possible SSH Brute Force

```spl
index=<linux_index> earliest=-24h
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<src_ip>\S+)"
| rex field=_raw "for (invalid user )?(?<user>\S+)"
| bin _time span=5m
| stats count dc(user) as unique_users values(user) as users by _time src_ip host
| where count >= 10
| sort - count
```

### Root Logins

```spl
index=<linux_index> earliest=-24h
| regex _raw="(Accepted .* for root|session opened for user root)"
| table _time host src_ip user _raw
| sort 0 - _time
```

## Linux Privilege and Account Activity

### Sudo Commands

```spl
index=<linux_index> earliest=-24h
("sudo:" OR "COMMAND=")
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)\s+:.*COMMAND=(?<command>.*)"
| table _time host sudo_user command _raw
| sort 0 - _time
```

### New User Account Creation

```spl
index=<linux_index> earliest=-7d
("useradd" OR "adduser" OR "new user" OR "new account")
| table _time host user _raw
| sort 0 - _time
```

### Password Changes

```spl
index=<linux_index> earliest=-7d
("passwd:" OR "password changed" OR "chpasswd")
| table _time host user _raw
| sort 0 - _time
```

## Linux Processes and Commands

### Auditd Process Creation

```spl
index=<linux_index> sourcetype=<audit_sourcetype> type=EXECVE earliest=-24h
| table _time host auid uid exe proctitle a0 a1 a2
| sort 0 - _time
```

### Suspicious Linux Commands

```spl
index=<linux_index> earliest=-24h
("curl" OR "wget" OR "bash -i" OR "nc " OR "ncat" OR "python -c" OR "perl -e" OR "base64 -d" OR "/dev/tcp/" OR "chmod +x")
| table _time host user process command _raw
| sort 0 - _time
```

### Shell History Activity

```spl
index=<linux_index> earliest=-24h
("history" OR "bash_history" OR ".sh_history")
| table _time host user command _raw
| sort 0 - _time
```

## Linux Persistence

### Cron Activity

```spl
index=<linux_index> earliest=-7d
("crontab" OR "/etc/cron" OR "/var/spool/cron" OR "CRON")
| table _time host user process command _raw
| sort 0 - _time
```

### Systemd Service Activity

```spl
index=<linux_index> earliest=-7d
("systemctl" OR ".service")
| table _time host user process command _raw
| sort 0 - _time
```

### SSH Key Activity

```spl
index=<linux_index> earliest=-7d
("authorized_keys" OR "ssh-keygen" OR "ssh-add")
| table _time host user process command _raw
| sort 0 - _time
```
