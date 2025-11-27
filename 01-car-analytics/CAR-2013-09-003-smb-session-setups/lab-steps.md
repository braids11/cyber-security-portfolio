# Lab Steps – CAR-2013-09-003 (SMB Session Setups)

## 1. Lab Environment

**Hypervisor:** ESXi on Mac Mini 2018  
**VMs:**
- Kali Linux – Attacker (IP: xxx.xxx.xxx.xxx)
- Windows 10 – Client/Endpoint (IP: xxx.xxx.xxx.xxx)
- Windows Server – File Server/Target (IP: xxx.xxx.xxx.xxx)

**Monitoring:**
- Sysmon on Windows hosts
- (Optional) Zeek on a separate sensor or SIEM stack
- Wireshark/tshark on Windows/Kali

---

## 2. Pre-Configuration

### Windows Server
- Enabled SMB/file sharing.
- Created a shared folder: `\\SERVER\Share`.
- Created user accounts used for testing: `labuser1`, `labuser2`.

### Windows 10
- Joined same network.
- Confirmed access to `\\SERVER\Share`.

### Sysmon
- Installed Sysmon vX.X with SwiftOnSecurity config.
- Confirmed logs are written (e.g. Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon/Operational).

---

## 3. Generating Normal SMB Activity

From **Windows 10**:

1. Open `\\SERVER\Share` in File Explorer.
2. Create, open, and modify a few files.
3. Map network drive `Z:` to `\\SERVER\Share`.
4. Record timestamps.

From **Kali** (if using smbclient for legit-ish access):

```bash
smbclient //SERVER/Share -U labuser1
# browse, list files, quit

### SCRIPTING TECHNIQUES ###

$IPs = "10.0.0.10","10.0.0.11","10.0.0.12"
foreach ($ip in $IPs) {
  net use \\$ip\C$ /user:labuser1 Password123
}

### CAPTURING TELEMETERY ###

KALI - tshark -i eth0 -w smb_sessions_car-2013-09-003.pcap
WIRESHARK FILTER - tcp.port == 445 && (smb.cmd == 0x73 || smb2.cmd == 1)




