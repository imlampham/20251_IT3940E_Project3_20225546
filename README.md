# 20251_IT3940E_Project3_20225546
# Design and Implementation of an AI Detection Module Integrated with Snort IDS/IPS

## Overview
This project implements an **AI-powered Intrusion Prevention System (IPS)** that combines traditional **Snort 3** signature-based detection with **Machine Learning** techniques to detect and block web shell attacks, malicious file uploads in real-time.

### System Architecture
```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Attacker   │───────▶│   Snort AI  │────────▶│   Target    │
│             │         │     IPS     │         │    DVWA     │
│192.168.2.10 │         │             │         │ 192.168.2.20│
└─────────────┘         └─────────────┘         └─────────────┘
                               │
                               │
                    ┌──────────▼──────────┐
                    │   AI Analysis       │
                    │   ├─ ML Models      │
                    │   └─ Anomaly Det.   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Decision Engine   │
                    │   ├─ Scoring        │
                    │   ├─ Thresholds     │
                    │   └─ Auto-blocking  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Response System   │
                    │   ├─ Snort rules    │
                    │   └─ Logging        │
                    └─────────────────────┘
```
