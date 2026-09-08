# 🛡️ ElderShield

### Stop. Check. Protect.

**ElderShield is an open-source AI-assisted safety tool designed to help protect people, especially elderly users, from scams, phishing, impersonation and financial fraud.**

> **Show ElderShield what you are seeing, and it tells you what to do.**

---

## 🚨 Why ElderShield?

Modern scams are no longer limited to suspicious links.

A fraudster may contact someone through:

- 📱 SMS
- 💬 WhatsApp
- ☎️ Phone calls
- 📧 Email
- 🌐 Websites
- 📷 QR codes
- 💳 Payment requests
- 📲 Remote-access applications
- 👮 Fake police/government calls
- 🏦 Fake bank/KYC messages
- 💼 Fake job offers
- 📈 Investment scams
- 🎁 Prize/lottery scams
- 📦 Courier/customs scams

The most dangerous part is often not the message itself.

It is the **action the victim is being manipulated into taking**.

ElderShield therefore focuses on both:

> **What is this?**

and

> **What is this person trying to make me do?**

---

# 🎯 Core Principle

## STOP → CHECK → PROTECT

### 1. STOP

If something feels suspicious, stop before clicking, paying, sharing information or installing anything.

### 2. CHECK

Show or provide the suspicious content to ElderShield.

ElderShield can analyze:

- Screens
- Messages
- URLs
- QR codes
- Call descriptions
- Call audio in demo mode
- Combinations of evidence

### 3. PROTECT

ElderShield gives a simple recommendation:

- 🟢 **SAFE**
- 🟡 **CAUTION**
- 🟠 **HIGH RISK**
- 🔴 **CRITICAL**

The system also explains:

> **Why is this dangerous?**

and

> **What should I do now?**

---

# ☎️ Call Protection

One of ElderShield's long-term goals is to protect elderly users from financial fraud that begins with a phone call.

For example:

**Incoming call**

↓

**Caller claims to be from a bank**

↓

**Creates fear or urgency**

↓

**Attempts to manipulate the user**

↓

**Requests information or financial action**

ElderShield is designed to eventually provide:

> **“Should I answer this call?”**

and, after answering:

> **“Is this caller trying to manipulate me?”**

and:

> **“What should I do right now?”**

### Current status

The current Streamlit version provides **Call Guardian Demo Mode**.

Automatic real-time cellular call monitoring will be developed later as a native Android component, subject to Android permissions and platform capabilities.

---

# 📸 Screen Guardian

Users can provide a screenshot or camera image of suspicious content.

Examples:

- Fake bank login
- KYC warning
- Fake government notice
- Payment request
- QR code
- Remote-access instruction
- Suspicious website
- Fake prize message

ElderShield uses multimodal AI and safety rules to identify relevant signals.

---

# 📝 Message Guardian

Users can paste a suspicious:

- SMS
- WhatsApp message
- Email
- Social-media message

ElderShield looks for patterns such as:

- Urgency
- Threats
- Impersonation
- Credential requests
- Payment requests
- Suspicious links
- Remote-access requests
- Fake rewards
- Job/investment scams
- Courier scams
- Digital-arrest patterns

---

# 🔗 Link Guardian

ElderShield can analyze a URL for suspicious characteristics.

Examples include:

- Suspicious URL structure
- HTTP instead of HTTPS
- Raw IP addresses
- URL shorteners
- Excessive subdomains
- Suspicious account/security keywords
- Non-ASCII/IDN characteristics
- Possible organization-domain mismatch

The system does **not** treat a URL check as proof that a website is safe.

---

# 🏦 Organization Verification

ElderShield contains a conservative registry of known official domains for selected organizations.

For example, it can compare:

```text
Claimed organization:
SBI

Website:
suspicious-example.com
