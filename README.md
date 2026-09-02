# Microsoft Defender ASR Testing

Safe, evidence-driven validation cases for Microsoft Defender Attack Surface Reduction rules.

## Project status

- [Configured ASR baseline](ASR_RULE_BASELINE.md)
- [Validation worklog](WORKLOG.md)
- [Rule 01: Block Adobe Reader from creating child processes](rules/01-adobe-reader-child-process/README.md)
- [Rule 02: Block process creations originating from PsExec and WMI commands](rules/02-psexec-wmi-process-creation/README.md)

Every test uses inert behavior, records local and Microsoft Defender XDR evidence, and distinguishes a genuine block from an upstream application restriction.
