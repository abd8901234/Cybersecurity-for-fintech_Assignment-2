# Cybersecurity-for-fintech_Assignment-2
# 🔐 CY4053 – Assignment 2: Secure FinTech Mini-App  
### Name: **ABDULLAH NAWAZ**
### Roll No: **22I9840**
### Course: **Cybersecurity for FinTech**
### Instructor: **Dr, Usama Arshad**
### Institution: **FAST NUCES Islamabad**
---

## 🚀 Project Overview

This project is a **Secure FinTech ** built using **Streamlit** as part of the CY4053 course.  
It demonstrates the application of **secure coding principles**, **encryption**, **input sanitization**, and **secure user authentication** practices in financial web applications.

The app ensures data confidentiality, integrity, and controlled access through **cryptographic encryption** and **role-based access flow**.



## ⚙️ Features Implemented

### 🧱 Core Functionalities
- **User Registration & Login**
  - Secure password hashing using `bcrypt`
  - Strong password enforcement
  - Email validation and sanitization
- **Account Lockout Protection**
  - Locks the account temporarily after 5 failed login attempts
- **Profile Management**
  - Update email
  - Change password securely
- **Wallet Management (Encrypted Data)**
  - Create, view, and decrypt encrypted wallets
  - Data is encrypted using `Fernet (AES-128 CBC with HMAC)`
- **Transactions (Linked with Wallets)**
  - Each wallet can have multiple transactions (ID + numeric value)
  - Data stored in encrypted form
- **Secure File Upload**
  - Validates allowed file types (.png, .jpg, .jpeg, .pdf, .csv, .txt)
  - Rejects malicious uploads
- **Encryption/Decryption Tool**
  - Allows users to encrypt/decrypt custom text securely
- **Audit Logs**
  - Tracks all key user actions (login, logout, wallet creation, etc.)
  - Downloadable in Excel format
  

---

### 🧪 Manual Cybersecurity Testing – Summary of 20 Test Cases

| No | Test Case | Action Performed | Expected Outcome | Observed Result | Pass/Fail |
|----|------------|-----------------|-----------------|-----------------|------------|
| 1 | Input Validation – SQL Injection | Entered `' OR 1=1--` in login form | Input rejected / error handled | Error handled properly | ✅ Pass |
| 2 | Password Strength | Tried weak password `12345` on registration | Rejected / Warning shown | Warning displayed successfully | ✅ Pass |
| 3 | Special Character Input | Added `<script>` in username | Sanitized / rejected | Escaped output shown | ✅ Pass |
| 4 | Unauthorized Access | Opened dashboard without login | Redirected to login | Access blocked | ✅ Pass |
| 5 | Session Expiry | Idle for 5 minutes | Auto logout | Session cleared automatically | ✅ Pass |
| 6 | Logout Functionality | Pressed logout | Session destroyed | Redirect to login page | ✅ Pass |
| 7 | Data Confidentiality | Opened stored DB file | Passwords hashed / emails encrypted | Secure storage verified | ✅ Pass |
| 8 | File Upload Validation | Tried uploading `.exe` file | File rejected | Correct behavior observed | ✅ Pass |
| 9 | Error Message Leakage | Entered invalid query | Generic error shown (no stack trace) | No traceback displayed | ✅ Pass |
| 10 | Input Length Validation | Entered 5000 chars in field | Validation triggered | Safe handling without crash | ✅ Pass |
| 11 | Duplicate User Registration | Tried existing username | Error displayed | Proper duplicate warning | ✅ Pass |
| 12 | Number Field Validation | Entered letters in amount field | Rejected / error shown | Validation successful | ✅ Pass |
| 13 | Password Match Check | Mismatched confirm password | Registration blocked | Correct validation | ✅ Pass |
| 14 | Data Modification Attempt | Changed transaction ID manually | Access denied | Unauthorized change blocked | ✅ Pass |
| 15 | Email Validation | Entered invalid email `abc@` | Error displayed | Validation successful | ✅ Pass |
| 16 | Login Attempt Lockout | Five failed logins | Account locked | Lockout triggered | ✅ Pass |
| 17 | Secure Error Handling | Forced divide-by-zero | App did not crash – controlled message | Correct behavior | ✅ Pass |
| 18 | Encrypted Record Check | Viewed stored data file | Data unreadable (encrypted) | Verified encrypted values | ✅ Pass |
| 19 | Input Encoding | Used Unicode emoji input | App handled gracefully | No corruption observed | ✅ Pass |
| 20 | Empty Field Submission | Left required fields blank | Warning displayed | Correct behavior | ✅ Pass |

---

## 🧪 Manual Testing Overview

Manual security tests were performed according to the provided assignment document.  
Each test case verifies one of the implemented security features.

| Test Case | Example Scenario | Expected Result |
|------------|------------------|-----------------|
| SQL Injection | `' OR 1=1--` in login field | Unsafe input blocked |
| Input Sanitization | `<script>alert()</script>` | Removed safely |
| Account Lockout | 5 wrong passwords | Login blocked for 60s |
| Encrypted Record Check | Viewed raw DB | Data unreadable (ciphertext) |
| Secure Error Handling | Forced divide-by-zero | Safe handled message |
| Unauthorized Access | Access wallet without login | Denied |
| File Upload | Upload `.exe` | Blocked |

All test evidence (screenshots + results) are documented in:  https://github.com/abd8901234/Cybersecurity-for-fintech_Assignment-2
