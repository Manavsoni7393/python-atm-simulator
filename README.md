# 🏧 Python Banking & ATM Simulator

A feature-rich, object-oriented Command Line Interface (CLI) Banking and ATM Application built using Python. This application simulates a real-world core banking system and ATM terminal featuring custom exception handling, SHA-256 password hashing, transaction audit logs, inter-account transfers, and interactive security PIN challenges.

---

## ✨ Features

- **🔐 Robust Security & Data Protection**
  - **SHA-256 Hashing:** Raw passwords and PINs are never saved in memory or stored in plain text.
  - **Interactive Password Masking:** Supports asterisk (`*`) masked input using `pwinput` (with seamless fallback).
  - **PIN Security Verification:** Post-login PIN checks before sensitive transactions (Withdrawals, Transfers, PIN Changes).
  - **Account Lockout Protection:** Automatically locks an account after 3 consecutive failed PIN attempts.

- **🏦 Comprehensive Core Banking Operations**
  - **Account Registration:** Register accounts with auto-generated unique IDs (e.g., `ACC1001`), minimum initial deposit checks, and input validations.
  - **Authentication System:** Secure login using Account Number and Password combinations.
  - **Deposits & Withdrawals:** Enforces minimum balance requirements ($50.00 minimum threshold).
  - **Fund Transfers:** Direct account-to-account transfers with real-time sender/recipient balance updates.
  - **Credential Management:** Change Security PIN or Account Password directly within the portal.

- **📊 Audit Logging & System Admin**
  - **Mini-Statements / Audit Logs:** View a defensive-copy transaction history showing exact timestamps, transaction types, amounts, and updated balances.
  - **System Metrics Overview:** View central bank liquidity, total registered accounts, operational status, and user account directories.

---

## 📁 Project Structure

```text
.
├── Atm.py          # Main application source code containing models, logic, and CLI
├── README.md       # Project documentation
└── requirements.txt # Optional dependencies (pwinput)
