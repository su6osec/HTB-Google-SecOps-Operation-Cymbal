-- ==============================================================================
-- Operation Cymbal: Cold Room — Chronicle UDM Search Queries Library
-- HackTheBox & Google Cloud Security Community Joint Incident Response CTF
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- SCENARIO 1: DECEPTIVE CLICK (INVESTIGATION)
-- ------------------------------------------------------------------------------

-- Flag 1: Hostname of Compromised Denver Workstation
-- Identify hidden encoded PowerShell process launch on Denver endpoints
metadata.event_type = "PROCESS_LAUNCH" AND target.process.command_line = /.*powershell.*-enc.*/

-- Flag 2: Referer Domain of Malicious Update Archive
-- Analyze web proxy traffic from CYM-DEN-W10-042 to find the compromised blog
principal.hostname = "CYM-DEN-W10-042.CYMBAL.CORP" AND metadata.event_type = "NETWORK_HTTP"

-- Flag 3: Process Hollowing Target Process ID (svchost.exe)
-- Identify injection from d27e15eb.exe into svchost.exe (Sysmon Event ID 8)
principal.hostname = "CYM-DEN-W10-042.CYMBAL.CORP" AND (principal.process.file.full_path = /.*d27e15eb\.exe/ OR target.process.file.full_path = /.*svchost\.exe/)

-- Flag 4: Kerberoasting Service Principal Name (SPN)
-- Query Kerberos TGS ticket requests with RC4 (0x17) encryption on CYM-DC-01
metadata.product_event_type = "4769" AND target.hostname = "CYM-DC-01"

-- Flag 5: Lateral Movement Service Account
-- Search for authentication from Denver workstation to internal file server
principal.ip = "10.240.12.42" AND metadata.event_type = "USER_LOGIN"

-- Flag 6: Financial Staging Zip Archive
-- Locate PowerShell Compress-Archive command staging sensitive audits on CYM-FS-01
principal.hostname = "CYM-FS-01.cymbal.corp" AND (target.process.command_line = /.*zip.*/ OR target.file.full_path = /.*\.zip/)


-- ------------------------------------------------------------------------------
-- SCENARIO 2: OAUTH HEIST (THREAT HUNTING)
-- ------------------------------------------------------------------------------

-- Flag 7 (S2-F1): Credential Phishing Domain
-- Search for HTTP POST requests from victim Elena Rostov
principal.user.userid = "elena.rostova" AND network.http.method = "POST"

-- Flag 8 (S2-F2): Deleted Security Alert Email Subject
-- Audit Gmail events where third-party OAuth app ToogleBox Recall permanently purged mail
metadata.log_type = "GSUITE_GMAIL" AND principal.user.userid = "elena.rostova@cymbal-investments.com" AND (security_result.action = "TRASH" OR security_result.action = "DELETE")

-- Flag 9 (S2-F3): Stolen Internal Cloud Architecture Document
-- Track Google Drive access from attacker proxy infrastructure IP 23.234.119.110
principal.ip = "23.234.119.110" OR target.ip = "23.234.119.110"

-- Flag 10 (S2-F4): Privileged Database Service Account
-- Investigate authentication targeting production database CYM-DB-01 from Elena workstation
target.hostname = /.*CYM-DB.*/ AND metadata.event_type = "USER_LOGIN"

-- Flag 11 (S2-F5): Raw Database Dump File Name
-- Inspect sqlcmd.exe execution creating compressed database backups on CYM-DB-01
target.process.command_line = /.*sqlcmd.*/ AND principal.hostname = /.*CYM-DB.*/

-- Flag 12 (S2-F6): Full Database Dump Exfiltration URL
-- Identify high-volume Zscaler HTTP POST transfers from database staging host 10.240.12.100
principal.user.userid = "svc_dbadmin" AND metadata.event_type = "NETWORK_HTTP"


-- ------------------------------------------------------------------------------
-- SCENARIO 3: ROGUE SYNTHESIS (AI MISUSE)
-- ------------------------------------------------------------------------------

-- Flag 13 (S3-F1): Developer Username Initiating Model Request
-- Trace connections to Google Gemini and Generative Language API endpoints
target.hostname = /.*generativelanguage\.googleapis\.com/ OR target.url = /.*generativelanguage.*/

-- Flag 14 (S3-F2): Downloaded Malicious VSIX Extension Package
-- Identify Visual Studio Code extension package downloads on CYM-DEV-WS-019
target.file.full_path = /.*syntaxoptimizer.*/ OR target.url = /.*syntaxoptimizer.*/

-- Flag 15 (S3-F3): Compiled Executable Dropped into Staging Directory
-- Trace Node.js spawning MinGW GCC compiler on developer endpoint
target.process.command_line = /.*gcc.*cache_worker.*/

-- Flag 16 (S3-F4): Local Cloud SDK File Read to Harvest Tokens
-- Identify commands reading credentials database and triggering Alert T1003.008
target.file.full_path = /.*(credentials|\.db|tokens).*/ OR target.process.command_line = /.*(credentials|\.db|tokens).*/

-- Flag 17 (S3-F5): Masqueraded Telemetry Exfiltration Domain
-- Trace outbound HTTP POST requests to fake telemetry endpoints
metadata.event_type = "NETWORK_HTTP" AND target.url = /.*telemetry.*/

-- Flag 18 (S3-F6): Overwritten Persistence Script on CI Runner
-- Track WinRM lateral movement with svc_cicd_deploy to CYM-CI-RUNNER-01
principal.hostname = /CYM-CI-RUNNER-01/ OR target.hostname = /CYM-CI-RUNNER-01/
