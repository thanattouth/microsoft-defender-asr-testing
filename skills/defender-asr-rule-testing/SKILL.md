---
name: defender-asr-rule-testing
description: Plan, research, implement, document, and hand off one Microsoft Defender Attack Surface Reduction rule validation at a time in this repository.
---

# Defender ASR rule testing

Use this workflow whenever adding or revising an ASR rule test in this project.

## Start from project state

Read `ASR_RULE_BASELINE.md`, `WORKLOG.md`, the root `README.md`, and the target rule folder. Confirm that unrelated user changes remain untouched.

## Work one rule at a time

1. Confirm the rule name, GUID, configured mode, supported Windows versions, dependencies, and any alert or notification caveats.
2. Research current Microsoft Learn documentation. Use vendor documentation when application behavior affects the trigger. Record links and the research date in the rule document.
3. Write down the objective, prerequisites, expected process or file behavior, local evidence, portal evidence, safety boundary, cleanup, and explicit success criteria before implementation.
4. Define a primary trigger and at least one fallback. Treat a trigger stopped by an upstream application control as `Inconclusive`, not as an ASR failure.
5. Implement the smallest inert test that reaches the protected behavior. Prefer visible benign programs or marker files. Do not include credential access, persistence, destructive encryption, uncontrolled downloads, or configuration weakening.
6. Do not change Defender, Intune, Office, Adobe, or tenant policy by default. If a diagnostic control run requires a policy change, document it as optional and require the operator's deliberate authorization and a rollback plan.
7. Make scripts collect their own preflight state and evidence where practical. Use result states `Blocked`, `Audited`, `Not triggered`, and `Inconclusive` consistently.
8. Validate syntax and deterministic artifact generation locally when the platform permits. Clearly state which Windows behavior still requires operator validation.
9. Update `WORKLOG.md` for durable progress. Update the baseline only when its recorded configuration changes. Keep detailed findings in the target rule folder rather than growing this skill.

## Handoff contract

At the end of each rule, provide:

- one Conventional Commit message suitable for the user to commit and push;
- exact Windows execution steps;
- exact local Event Viewer or PowerShell evidence checks;
- a Microsoft Defender XDR Advanced Hunting query when applicable;
- expected successful outcomes and a short troubleshooting decision table;
- cleanup steps and any remaining validation limitation.

Do not call a rule operationally validated until evidence from a Windows test device satisfies its documented success criteria.
