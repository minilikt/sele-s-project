"""
MITRE ATT&CK technique mapping data for the SIEM backend.

Provides lookup utilities and investigation guidance for each mapped technique.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ── Technique database ────────────────────────────────────────────────────────

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to "
            "accounts when passwords are unknown or when password hashes are "
            "obtained. Techniques include password guessing, password spraying, "
            "and credential stuffing."
        ),
        "detection": (
            "Monitor authentication logs for a high volume of failed login "
            "attempts targeting a single account or originating from a single "
            "source IP within a short time window."
        ),
        "investigation_steps": [
            "Identify the target account(s) and source IP(s) involved.",
            "Check if any login attempt eventually succeeded.",
            "Review the time window and frequency of failed attempts.",
            "Determine if the source IP is internal or external.",
            "Check for login attempts from unusual geographic locations.",
            "Verify whether the targeted account has MFA enabled.",
            "Review account lockout policies and recent lockout events.",
            "Correlate with VPN or remote access logs for the same timeframe.",
        ],
        "recommended_response": [
            "Lock or disable the targeted account(s) immediately.",
            "Block the offending source IP at the perimeter firewall.",
            "Reset the password of any account that may have been compromised.",
            "Enable multi-factor authentication on the affected account(s).",
            "Review and strengthen account lockout policies.",
            "Monitor for subsequent suspicious activity from the same source.",
            "Notify the account owner and the security team.",
        ],
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may guess passwords to attempt access to accounts. "
            "Without knowledge of the password, they may systematically guess "
            "common passwords or those related to the target."
        ),
        "detection": (
            "Monitor for many failed authentication attempts from a single "
            "source, especially against high-value accounts."
        ),
        "investigation_steps": [
            "Identify the target account and source of the guessing attempts.",
            "Check how many unique passwords were attempted.",
            "Determine if the guessing follows a common wordlist pattern.",
            "Verify whether any attempt succeeded.",
            "Assess the account's role and privilege level.",
        ],
        "recommended_response": [
            "Lock the targeted account and reset its password.",
            "Block the source IP address.",
            "Implement account lockout thresholds.",
            "Deploy multi-factor authentication.",
            "Audit password policies for complexity requirements.",
        ],
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use a single or small list of commonly used "
            "passwords against many different accounts to acquire valid "
            "credentials. This avoids account lockout thresholds."
        ),
        "detection": (
            "Monitor for a single password attempted against many accounts in "
            "a short time window, or a slow, distributed pattern of failures "
            "across accounts."
        ),
        "investigation_steps": [
            "Identify the scope — how many accounts were targeted.",
            "Check if the source IP or user-agent is consistent.",
            "Determine if any account was successfully authenticated.",
            "Look for follow-on activity from compromised accounts.",
            "Verify whether this activity comes from a known penetration test.",
        ],
        "recommended_response": [
            "Reset passwords for all accounts targeted.",
            "Enable MFA on all affected accounts.",
            "Block offending source IPs or ranges.",
            "Review and enforce strong password policies.",
            "Consider deploying a CAPTCHA or adaptive authentication.",
        ],
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "to gain initial access, persistence, privilege escalation, or "
            "defense evasion."
        ),
        "detection": (
            "Monitor for unusual account activity such as logins at abnormal "
            "times, from unusual locations, or with unusual access patterns "
            "following a credential-based attack."
        ),
        "investigation_steps": [
            "Determine how the credentials were obtained (phishing, brute force, etc.).",
            "Review the account's recent activity and accessed resources.",
            "Check for privilege escalation or lateral movement.",
            "Identify any new accounts created using the compromised account.",
            "Verify whether the legitimate user was active at the same time.",
            "Review the account's group memberships and permissions.",
        ],
        "recommended_response": [
            "Immediately reset the compromised account's credentials.",
            "Revoke all active sessions and tokens.",
            "Enable MFA on the account.",
            "Audit all actions performed by the compromised account.",
            "Scan for persistence mechanisms (new accounts, scheduled tasks, etc.).",
            "Notify the legitimate account owner.",
        ],
    },
    "T1136": {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create accounts to maintain access to victim "
            "systems. Created accounts may be used for persistence or to "
            "escalate privileges."
        ),
        "detection": (
            "Monitor for account creation events (e.g., Event ID 4720 on "
            "Windows). Pay special attention to accounts created outside "
            "business hours or by unusual parent accounts."
        ),
        "investigation_steps": [
            "Identify who created the account and from which system.",
            "Determine if the creation was authorised via a change request.",
            "Check if the new account was granted elevated privileges.",
            "Review the creating account's recent activity for compromise.",
            "Look for the new account being used immediately after creation.",
        ],
        "recommended_response": [
            "Disable the newly created account pending investigation.",
            "Verify the legitimacy of the creation with the responsible team.",
            "If unauthorised, disable the creating account and reset its credentials.",
            "Audit all actions performed by both accounts.",
            "Review account creation policies and approval workflows.",
        ],
    },
    "T1136.001": {
        "id": "T1136.001",
        "name": "Local Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create a local account to maintain access. Local "
            "accounts are configured for use on individual systems."
        ),
        "detection": (
            "Monitor for Event ID 4720 (account created) and correlate with "
            "Event ID 4732 (member added to security group)."
        ),
        "investigation_steps": [
            "Confirm the local account was not expected from a provisioning workflow.",
            "Check if the new account was added to any privileged local groups.",
            "Review the creating user's session for signs of compromise.",
        ],
        "recommended_response": [
            "Disable the local account immediately.",
            "Investigate the host for additional persistence mechanisms.",
            "Remove the account from any groups it was added to.",
        ],
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": (
            "Adversaries may abuse the Windows Task Scheduler to perform task "
            "scheduling for initial or recurring execution of malicious code."
        ),
        "detection": (
            "Monitor for scheduled task creation events (Event ID 4698) "
            "especially those created outside business hours or with "
            "suspicious command lines."
        ),
        "investigation_steps": [
            "Identify the task name, command/action, and trigger schedule.",
            "Determine who created the task and when.",
            "Check if the command references external URLs or encoded payloads.",
            "Verify whether the task runs with elevated privileges.",
            "Review the host for other signs of compromise.",
        ],
        "recommended_response": [
            "Delete or disable the suspicious scheduled task.",
            "Analyse the payload/command the task was configured to run.",
            "Isolate the host if malicious activity is confirmed.",
            "Scan the host for additional persistence mechanisms.",
            "Review task scheduler audit policies.",
        ],
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for "
            "execution. PowerShell can be used to download and execute code "
            "from the Internet, bypass security controls, and perform "
            "reconnaissance."
        ),
        "detection": (
            "Monitor for suspicious PowerShell activity including encoded "
            "commands, execution policy bypasses, download cradles, and "
            "hidden window styles."
        ),
        "investigation_steps": [
            "Decode any Base64-encoded command-line arguments.",
            "Identify what the PowerShell command was designed to do.",
            "Check for network connections made by the PowerShell process.",
            "Review the parent process that launched PowerShell.",
            "Look for downloaded files or payloads.",
            "Check PowerShell script block logging (Event ID 4104) for full script content.",
        ],
        "recommended_response": [
            "Kill the malicious PowerShell process immediately.",
            "Isolate the affected host from the network.",
            "Collect forensic artifacts (memory dump, script block logs).",
            "Remove any downloaded payloads or persistence mechanisms.",
            "Enable Constrained Language Mode on the host.",
            "Review PowerShell execution policies across the environment.",
        ],
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries. These are often built into the "
            "operating system."
        ),
        "detection": (
            "Monitor process creation events for interpreter invocations "
            "(cmd.exe, powershell.exe, wscript.exe, cscript.exe) with "
            "suspicious arguments."
        ),
        "investigation_steps": [
            "Identify the interpreter and the full command line.",
            "Determine the parent process and user context.",
            "Check if the activity correlates with legitimate admin work.",
            "Review network and file-system activity from the process.",
        ],
        "recommended_response": [
            "Terminate the suspicious process.",
            "Block the script or binary hash if malicious.",
            "Restrict interpreter access via AppLocker or WDAC.",
            "Enable enhanced command-line audit logging.",
        ],
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation, Defense Evasion",
        "description": (
            "Adversaries may circumvent mechanisms designed to control "
            "elevate privileges to gain higher-level permissions."
        ),
        "detection": (
            "Monitor for process creation with unusual integrity levels, "
            "unexpected UAC bypass artifacts, or privilege assignment events."
        ),
        "investigation_steps": [
            "Determine which elevation mechanism was abused.",
            "Identify the account and host involved.",
            "Check for preceding compromise indicators (phishing, malware).",
            "Review group policy settings for UAC configuration.",
        ],
        "recommended_response": [
            "Revoke elevated privileges from the compromised account.",
            "Patch or reconfigure the abused elevation mechanism.",
            "Enforce least-privilege policies.",
            "Deploy endpoint protection rules for known bypass techniques.",
        ],
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into remote services "
            "such as RDP, SSH, SMB, or WinRM to move laterally within an "
            "environment."
        ),
        "detection": (
            "Monitor for remote logon events (Type 10 for RDP, Type 3 for "
            "network logons) from unusual sources or at unusual times."
        ),
        "investigation_steps": [
            "Identify the source and destination hosts.",
            "Determine the account used and its normal behaviour baseline.",
            "Check for data access or exfiltration on the destination host.",
            "Review firewall and VPN logs for external connections.",
            "Look for subsequent lateral movement from the destination.",
        ],
        "recommended_response": [
            "Disable remote access for the compromised account.",
            "Isolate affected hosts from the network.",
            "Reset credentials for any account used in the lateral movement.",
            "Review and restrict remote access policies.",
            "Enable network-level authentication for RDP.",
        ],
    },
}


# ── Public lookup functions ───────────────────────────────────────────────────


def get_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Return the full technique record, or *None* if not found."""
    return TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """Return all techniques whose tactic field contains *tactic* (case-insensitive)."""
    tactic_lower = tactic.lower()
    return [
        t for t in TECHNIQUES.values()
        if tactic_lower in t["tactic"].lower()
    ]


def get_investigation_steps(technique_id: str) -> List[str]:
    """Return investigation steps for a technique, or an empty list."""
    tech = TECHNIQUES.get(technique_id)
    if tech is None:
        return []
    return tech["investigation_steps"]


def get_all_techniques() -> List[Dict[str, Any]]:
    """Return every mapped technique."""
    return list(TECHNIQUES.values())
