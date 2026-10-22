# KC7 Write-ups

Security investigation write-ups from [KC7](https://www.kc7cyber.com/) — a free, browser-based
training platform that teaches threat hunting and SOC analysis through realistic, narrative-driven
cases investigated with KQL (Kusto Query Language).

Each write-up documents my own investigation process: the hypotheses I formed, the KQL queries I
ran, what the data showed, and how one finding led to the next — not a plain list of submitted
answers.

## 🏅 Security Analyst I

Path completed on KC7 (verified on my dashboard): **18 October 2026**.

| # | Module | Write-up |
|---|---|---|
| 1 | A Rap Beef: An Intro to Security Investigations | [✅ Read](paths/security-analyst-i/modules/01-a-rap-beef.md) |
| 2 | How to play KC7 | [✅ Read](paths/security-analyst-i/modules/02-how-to-play-kc7.md) |
| 3 | CloutHaus: Social Media leads to Compromise | [✅ Read](paths/security-analyst-i/modules/03-clouthaus.md) |
| 4 | A Scandal in Valdoria: A Political Mystery | [✅ Read](paths/security-analyst-i/modules/04-a-scandal-in-valdoria.md) |
| 5 | VirusTotal Fundamentals | [✅ Read](paths/security-analyst-i/modules/05-virustotal-fundamentals.md) |
| 6 | KQL 101: An introduction to Kusto Query Language | [✅ Read](paths/security-analyst-i/modules/06-kql-101.md) |
| 7 | Jojo's Hospital: A Ransomware Investigation | ⏳ Coming soon |

Reusable KQL queries live alongside each module under [`paths/security-analyst-i/queries/`](paths/security-analyst-i/queries/).

## Skills practiced

- Writing and adapting KQL queries (`where`, `project`, `summarize`, `let`, `distinct`, `in`, `has`, `has_any`, `between`)
- Pivoting across log sources (web traffic, email, DNS, authentication) from a single indicator to rebuild a full attack chain
- Forming and testing hypotheses, then scoping an investigation around what actually advances it
- Reconstructing attack timelines and extracting IOCs from raw logs
- Mapping observed behavior to MITRE ATT&CK tactics and techniques
- Writing findings up for a non-technical audience, with defensive recommendations

## Repository structure

Write-ups are organized by KC7 learning path, so new paths can be added without touching existing
ones:

```
paths/
└── <path-slug>/
    ├── modules/   ← one write-up per module
    ├── queries/   ← commented, reusable .kql files
    └── images/    ← cropped result screenshots, one folder per module
```

See [`CLAUDE.md`](CLAUDE.md) for the full methodology and ground rules behind these write-ups.

## About me

I'm Miracle, a 2nd-year cybersecurity student at IFRI (Université d'Abomey-Calavi, Benin).

---
*Last updated: 2026-10-22.*
