# Microsoft Defender ASR test baseline

Recorded: 2026-09-02 (Asia/Bangkok)

| # | Attack Surface Reduction rule | Configured mode |
|---:|---|---|
| 1 | Block Adobe Reader from creating child processes | Block |
| 2 | Block process creations originating from PSExec and WMI commands | Block |
| 3 | Block execution of potentially obfuscated scripts | Block |
| 4 | Block persistence through WMI event subscription | Block |
| 5 | Block Win32 API calls from Office macros | Block |
| 6 | Block Office applications from creating executable content | Block |
| 7 | Block credential stealing from the Windows local security authority subsystem | Block |
| 8 | Block use of copied or impersonated system tools | Block |
| 9 | Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Block |
| 10 | Block JavaScript or VBScript from launching downloaded executable content | Block |
| 11 | Block Office communication application from creating child processes | Block |
| 12 | Block Office applications from injecting code into other processes | Block |
| 13 | Block all Office applications from creating child processes | Block |
| 14 | Block rebooting machine in Safe Mode | Block |
| 15 | Block untrusted and unsigned processes that run from USB | Block |
| 16 | Use advanced protection against ransomware | Block |
| 17 | Block executable content from email client and webmail | Block |
| 18 | Block abuse of exploited vulnerable signed drivers (Device) | Block |
| 19 | Enable Controlled Folder Access | Audit Mode |

## Testing convention

- Test one rule at a time.
- Use inert test artifacts and observable actions rather than destructive payloads.
- Record prerequisites, trigger steps, expected result, local Defender evidence, and Microsoft Defender portal evidence for every rule.
- Distinguish `Blocked`, `Audited`, `Not triggered`, and `Inconclusive` results.
