{
  "@timestamp": [
    "2025-12-16T14:09:29.991Z"
  ],
  "@version": [
    "1"
  ],
  "@version.keyword": [
    "1"
  ],
  "agent.ephemeral_id": [
    "ff21878a-b610-4417-bd2a-a9793f25d221"
  ],
  "agent.ephemeral_id.keyword": [
    "ff21878a-b610-4417-bd2a-a9793f25d221"
  ],
  "agent.id": [
    "8ef478b9-c113-4563-9178-38084c63c7d1"
  ],
  "agent.id.keyword": [
    "8ef478b9-c113-4563-9178-38084c63c7d1"
  ],
  "agent.name": [
    "LABWINCLIENT01"
  ],
  "agent.name.keyword": [
    "LABWINCLIENT01"
  ],
  "agent.type": [
    "filebeat"
  ],
  "agent.type.keyword": [
    "filebeat"
  ],
  "agent.version": [
    "9.2.2"
  ],
  "agent.version.keyword": [
    "9.2.2"
  ],
  "ecs.version": [
    "8.0.0"
  ],
  "ecs.version.keyword": [
    "8.0.0"
  ],
  "event.action": [
    "Process Create (rule: ProcessCreate)"
  ],
  "event.action.keyword": [
    "Process Create (rule: ProcessCreate)"
  ],
  "event.code": [
    "1"
  ],
  "event.code.keyword": [
    "1"
  ],
  "event.created": [
    "2025-12-16T14:09:31.149Z"
  ],
  "event.kind": [
    "event"
  ],
  "event.kind.keyword": [
    "event"
  ],
  "event.original": [
    "Process Create:\nRuleName: -\nUtcTime: 2025-12-16 14:09:29.988\nProcessGuid: {9AF533FD-6819-6941-5523-000000000700}\nProcessId: 14628\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nFileVersion: 10.0.26100.5074 (WinBuild.160101.0800)\nDescription: Windows PowerShell\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: PowerShell.EXE\nCommandLine: powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'\nCurrentDirectory: C:\\Users\\LabUser\\\nUser: LABWINCLIENT01\\LabUser\nLogonGuid: {9AF533FD-0620-6939-4B7D-210000000000}\nLogonId: 0x217d4b\nTerminalSessionId: 1\nIntegrityLevel: Medium\nHashes: MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77\nParentProcessGuid: {9AF533FD-3028-693C-C710-000000000700}\nParentProcessId: 9140\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"C:\\WINDOWS\\system32\\cmd.exe\" \nParentUser: LABWINCLIENT01\\LabUser"
  ],
  "event.original.keyword": [
    "Process Create:\nRuleName: -\nUtcTime: 2025-12-16 14:09:29.988\nProcessGuid: {9AF533FD-6819-6941-5523-000000000700}\nProcessId: 14628\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nFileVersion: 10.0.26100.5074 (WinBuild.160101.0800)\nDescription: Windows PowerShell\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: PowerShell.EXE\nCommandLine: powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'\nCurrentDirectory: C:\\Users\\LabUser\\\nUser: LABWINCLIENT01\\LabUser\nLogonGuid: {9AF533FD-0620-6939-4B7D-210000000000}\nLogonId: 0x217d4b\nTerminalSessionId: 1\nIntegrityLevel: Medium\nHashes: MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77\nParentProcessGuid: {9AF533FD-3028-693C-C710-000000000700}\nParentProcessId: 9140\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"C:\\WINDOWS\\system32\\cmd.exe\" \nParentUser: LABWINCLIENT01\\LabUser"
  ],
  "event.provider": [
    "Microsoft-Windows-Sysmon"
  ],
  "event.provider.keyword": [
    "Microsoft-Windows-Sysmon"
  ],
  "host.architecture": [
    "x86_64"
  ],
  "host.architecture.keyword": [
    "x86_64"
  ],
  "host.hostname": [
    "LABWINCLIENT01"
  ],
  "host.hostname.keyword": [
    "LABWINCLIENT01"
  ],
  "host.id": [
    "9af533fd-6323-4158-8545-e1c9fc2e39f3"
  ],
  "host.id.keyword": [
    "9af533fd-6323-4158-8545-e1c9fc2e39f3"
  ],
  "host.ip": [
    "fe80::563e:dfcf:326b:2504",
    "192.168.1.30"
  ],
  "host.ip.keyword": [
    "fe80::563e:dfcf:326b:2504",
    "192.168.1.30"
  ],
  "host.mac": [
    "00-0C-29-61-4E-4C"
  ],
  "host.mac.keyword": [
    "00-0C-29-61-4E-4C"
  ],
  "host.name": [
    "labwinclient01"
  ],
  "host.name.keyword": [
    "labwinclient01"
  ],
  "host.os.build": [
    "26200.7462"
  ],
  "host.os.build.keyword": [
    "26200.7462"
  ],
  "host.os.family": [
    "windows"
  ],
  "host.os.family.keyword": [
    "windows"
  ],
  "host.os.kernel": [
    "10.0.26100.7462 (WinBuild.160101.0800)"
  ],
  "host.os.kernel.keyword": [
    "10.0.26100.7462 (WinBuild.160101.0800)"
  ],
  "host.os.name": [
    "Windows 11 Pro"
  ],
  "host.os.name.keyword": [
    "Windows 11 Pro"
  ],
  "host.os.platform": [
    "windows"
  ],
  "host.os.platform.keyword": [
    "windows"
  ],
  "host.os.type": [
    "windows"
  ],
  "host.os.type.keyword": [
    "windows"
  ],
  "host.os.version": [
    "10.0"
  ],
  "host.os.version.keyword": [
    "10.0"
  ],
  "input.type": [
    "winlog"
  ],
  "input.type.keyword": [
    "winlog"
  ],
  "log.level": [
    "information"
  ],
  "log.level.keyword": [
    "information"
  ],
  "message": [
    "Process Create:\nRuleName: -\nUtcTime: 2025-12-16 14:09:29.988\nProcessGuid: {9AF533FD-6819-6941-5523-000000000700}\nProcessId: 14628\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nFileVersion: 10.0.26100.5074 (WinBuild.160101.0800)\nDescription: Windows PowerShell\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: PowerShell.EXE\nCommandLine: powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'\nCurrentDirectory: C:\\Users\\LabUser\\\nUser: LABWINCLIENT01\\LabUser\nLogonGuid: {9AF533FD-0620-6939-4B7D-210000000000}\nLogonId: 0x217d4b\nTerminalSessionId: 1\nIntegrityLevel: Medium\nHashes: MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77\nParentProcessGuid: {9AF533FD-3028-693C-C710-000000000700}\nParentProcessId: 9140\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"C:\\WINDOWS\\system32\\cmd.exe\" \nParentUser: LABWINCLIENT01\\LabUser"
  ],
  "message.keyword": [
    "Process Create:\nRuleName: -\nUtcTime: 2025-12-16 14:09:29.988\nProcessGuid: {9AF533FD-6819-6941-5523-000000000700}\nProcessId: 14628\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nFileVersion: 10.0.26100.5074 (WinBuild.160101.0800)\nDescription: Windows PowerShell\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: PowerShell.EXE\nCommandLine: powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'\nCurrentDirectory: C:\\Users\\LabUser\\\nUser: LABWINCLIENT01\\LabUser\nLogonGuid: {9AF533FD-0620-6939-4B7D-210000000000}\nLogonId: 0x217d4b\nTerminalSessionId: 1\nIntegrityLevel: Medium\nHashes: MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77\nParentProcessGuid: {9AF533FD-3028-693C-C710-000000000700}\nParentProcessId: 9140\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"C:\\WINDOWS\\system32\\cmd.exe\" \nParentUser: LABWINCLIENT01\\LabUser"
  ],
  "tags": [
    "sysmon",
    "beats_input_codec_plain_applied"
  ],
  "tags.keyword": [
    "sysmon",
    "beats_input_codec_plain_applied"
  ],
  "winlog.channel": [
    "Microsoft-Windows-Sysmon/Operational"
  ],
  "winlog.channel.keyword": [
    "Microsoft-Windows-Sysmon/Operational"
  ],
  "winlog.computer_name": [
    "LABWINCLIENT01"
  ],
  "winlog.computer_name.keyword": [
    "LABWINCLIENT01"
  ],
  "winlog.event_data.CommandLine": [
    "powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'"
  ],
  "winlog.event_data.CommandLine.keyword": [
    "powershell  -Command Invoke-WebRequest -Uri 'https://github.com/braids11/detection-engineering-portfolio/blob/main/README.md' -OutFile 'C:/Users/LabUser/Desktop/readme.txt'; Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'"
  ],
  "winlog.event_data.Company": [
    "Microsoft Corporation"
  ],
  "winlog.event_data.Company.keyword": [
    "Microsoft Corporation"
  ],
  "winlog.event_data.CurrentDirectory": [
    "C:\\Users\\LabUser\\"
  ],
  "winlog.event_data.CurrentDirectory.keyword": [
    "C:\\Users\\LabUser\\"
  ],
  "winlog.event_data.Description": [
    "Windows PowerShell"
  ],
  "winlog.event_data.Description.keyword": [
    "Windows PowerShell"
  ],
  "winlog.event_data.FileVersion": [
    "10.0.26100.5074 (WinBuild.160101.0800)"
  ],
  "winlog.event_data.FileVersion.keyword": [
    "10.0.26100.5074 (WinBuild.160101.0800)"
  ],
  "winlog.event_data.Hashes": [
    "MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77"
  ],
  "winlog.event_data.Hashes.keyword": [
    "MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=AFACF6DC9041114B198160AAB4D0AE77"
  ],
  "winlog.event_data.Image": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "winlog.event_data.Image.keyword": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "winlog.event_data.IntegrityLevel": [
    "Medium"
  ],
  "winlog.event_data.IntegrityLevel.keyword": [
    "Medium"
  ],
  "winlog.event_data.LogonGuid": [
    "{9AF533FD-0620-6939-4B7D-210000000000}"
  ],
  "winlog.event_data.LogonGuid.keyword": [
    "{9AF533FD-0620-6939-4B7D-210000000000}"
  ],
  "winlog.event_data.LogonId": [
    "0x217d4b"
  ],
  "winlog.event_data.LogonId.keyword": [
    "0x217d4b"
  ],
  "winlog.event_data.OriginalFileName": [
    "PowerShell.EXE"
  ],
  "winlog.event_data.OriginalFileName.keyword": [
    "PowerShell.EXE"
  ],
  "winlog.event_data.ParentCommandLine": [
    "\"C:\\WINDOWS\\system32\\cmd.exe\" "
  ],
  "winlog.event_data.ParentCommandLine.keyword": [
    "\"C:\\WINDOWS\\system32\\cmd.exe\" "
  ],
  "winlog.event_data.ParentImage": [
    "C:\\Windows\\System32\\cmd.exe"
  ],
  "winlog.event_data.ParentImage.keyword": [
    "C:\\Windows\\System32\\cmd.exe"
  ],
  "winlog.event_data.ParentProcessGuid": [
    "{9AF533FD-3028-693C-C710-000000000700}"
  ],
  "winlog.event_data.ParentProcessGuid.keyword": [
    "{9AF533FD-3028-693C-C710-000000000700}"
  ],
  "winlog.event_data.ParentProcessId": [
    "9140"
  ],
  "winlog.event_data.ParentProcessId.keyword": [
    "9140"
  ],
  "winlog.event_data.ParentUser": [
    "LABWINCLIENT01\\LabUser"
  ],
  "winlog.event_data.ParentUser.keyword": [
    "LABWINCLIENT01\\LabUser"
  ],
  "winlog.event_data.ProcessGuid": [
    "{9AF533FD-6819-6941-5523-000000000700}"
  ],
  "winlog.event_data.ProcessGuid.keyword": [
    "{9AF533FD-6819-6941-5523-000000000700}"
  ],
  "winlog.event_data.ProcessId": [
    "14628"
  ],
  "winlog.event_data.ProcessId.keyword": [
    "14628"
  ],
  "winlog.event_data.Product": [
    "Microsoft® Windows® Operating System"
  ],
  "winlog.event_data.Product.keyword": [
    "Microsoft® Windows® Operating System"
  ],
  "winlog.event_data.RuleName": [
    "-"
  ],
  "winlog.event_data.RuleName.keyword": [
    "-"
  ],
  "winlog.event_data.TerminalSessionId": [
    "1"
  ],
  "winlog.event_data.TerminalSessionId.keyword": [
    "1"
  ],
  "winlog.event_data.User": [
    "LABWINCLIENT01\\LabUser"
  ],
  "winlog.event_data.User.keyword": [
    "LABWINCLIENT01\\LabUser"
  ],
  "winlog.event_data.UtcTime": [
    "2025-12-16 14:09:29.988"
  ],
  "winlog.event_data.UtcTime.keyword": [
    "2025-12-16 14:09:29.988"
  ],
  "winlog.event_id": [
    "1"
  ],
  "winlog.event_id.keyword": [
    "1"
  ],
  "winlog.opcode": [
    "Info"
  ],
  "winlog.opcode.keyword": [
    "Info"
  ],
  "winlog.process.pid": [
    3332
  ],
  "winlog.process.thread.id": [
    3808
  ],
  "winlog.provider_guid": [
    "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
  ],
  "winlog.provider_guid.keyword": [
    "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
  ],
  "winlog.provider_name": [
    "Microsoft-Windows-Sysmon"
  ],
  "winlog.provider_name.keyword": [
    "Microsoft-Windows-Sysmon"
  ],
  "winlog.record_id": [
    15133
  ],
  "winlog.task": [
    "Process Create (rule: ProcessCreate)"
  ],
  "winlog.task.keyword": [
    "Process Create (rule: ProcessCreate)"
  ],
  "winlog.user.domain": [
    "NT AUTHORITY"
  ],
  "winlog.user.domain.keyword": [
    "NT AUTHORITY"
  ],
  "winlog.user.identifier": [
    "S-1-5-18"
  ],
  "winlog.user.identifier.keyword": [
    "S-1-5-18"
  ],
  "winlog.user.name": [
    "SYSTEM"
  ],
  "winlog.user.name.keyword": [
    "SYSTEM"
  ],
  "winlog.user.type": [
    "User"
  ],
  "winlog.user.type.keyword": [
    "User"
  ],
  "winlog.version": [
    5
  ],
  "_id": "dEV-J5sBaw0IOPFNyB26",
  "_ignored": [
    "event.original.keyword",
    "message.keyword"
  ],
  "_index": "filebeat-9.2.2-2025.12.16",
  "_score": null
}