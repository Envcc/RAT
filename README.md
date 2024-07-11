# RAT Client and C2 Server - Ultimate Covert Command & Control Toolkit 🚀

Welcome to the ultimate covert Command & Control (C2) toolkit! This repository is a comprehensive suite for those who are keen on mastering the art of stealthy communication and control over remote systems. Designed with advanced techniques in mind, this toolkit provides everything a sophisticated hacker needs to establish an undetectable command channel between the client and server.

## Features

### 🛡️ Advanced Anti-Debugging and Anti-VM Techniques
- Bypass conventional debugging attempts with robust anti-debugging mechanisms.
- Detect and evade virtual machine environments to ensure your client runs undetected on genuine targets.

### 🔒 Strong AES Encryption
- Secure your communications with AES encryption, ensuring that all data transferred between the client and server is completely secure and unreadable to prying eyes.

### 📨 Stealthy ICMP Communication
- Use ICMP packets for covert communication. Avoid detection by standard network monitoring tools and firewalls with this sophisticated method of data transfer.

### 🎭 Polymorphic Shellcode Mutation
- Evade signature-based detection systems by continuously altering the shellcode. This polymorphic approach ensures that your payload remains undetected and effective.

### 💡 Dynamic Code Loading
- Load and execute code dynamically from files, allowing for easy updates and expansions of functionality without the need to redeploy the client.

### 🛠️ Command Execution
- Execute arbitrary shell commands received from the C2 server, giving you full control over the remote system.

## How It Works

### Client
- Implements anti-debugging and anti-VM checks.
- Encrypts and decrypts messages using AES.
- Sends and receives ICMP packets to communicate with the C2 server.
- Executes commands as directed by the C2 server.

### Server
- Listens for ICMP packets and decrypts incoming commands.
- Sends commands to the client to be executed.
- Uses AES encryption to ensure secure communication.

## Usage

### Compilation and Setup
1. **Compile the RAT Client**:
    ```bash
    gcc rat_client.c -o rat_client -lssl -lcrypto
    ```
2. **Run the RAT Client** (requires root privileges):
    ```bash
    sudo ./rat_client <command>
    ```
3. **Run the C2 Server**:
    ```bash
    sudo python3 c2_server.py
    ```

### Automation
- Scripts are provided to automate the compilation, execution, and communication process, making it easy to deploy and manage.

## Why This Toolkit?

This toolkit is designed for those who value stealth, security, and efficiency. Whether you are looking to learn more about advanced hacking techniques or need a reliable C2 setup for your projects, this repository has you covered. With features that rival the most sophisticated malware, you'll have a powerful tool at your disposal to conduct penetration testing and security research.

---

⚠️ **Disclaimer**: This toolkit is intended for educational purposes and authorized security testing only. Misuse of this software can result in severe legal consequences. Always obtain proper authorization before using it on any network or system.

---

Join the ranks of elite hackers with this cutting-edge C2 toolkit! Clone the repo, compile the client, and take command today!

---

**Contributors and Feedback**:
We welcome contributions and feedback. Feel free to open issues, submit pull requests, or reach out with suggestions to improve this toolkit.

---

Happy Hacking! 🚀

### Project Structure

```
RAT_Project/
├── RAT_Client/
│   ├── rat_client.c
│   ├── compile_rat.sh
│   └── run_rat.sh
├── C2_Server/
│   ├── c2_server.py
│   └── run_server.sh
└── automate.sh
└── README.md
```

### File Descriptions

1. **RAT_Client/rat_client.c**:
   - This is the C code for the Remote Access Trojan (RAT) client. It performs various functions such as encryption/decryption, sending/receiving ICMP packets, and anti-debugging measures.

2. **RAT_Client/compile_rat.sh**:
   - A shell script to compile the RAT client using `gcc`. It links the necessary libraries for OpenSSL.

3. **RAT_Client/run_rat.sh**:
   - A shell script to run the compiled RAT client executable. It takes a command as an argument.

4. **C2_Server/c2_server.py**:
   - This is the Python code for the Command and Control (C2) server. It listens for ICMP packets from the RAT client, decrypts the received messages, and sends encrypted responses back.

5. **C2_Server/run_server.sh**:
   - A shell script to run the C2 server with the necessary privileges.

6. **automate.sh**:
   - An automation script that compiles the RAT client, starts the C2 server, and runs the RAT client with a test command. It also handles cleanup by stopping the C2 server after execution.

7. **README.md**:
   - A markdown file providing an overview of the project, setup instructions, and usage guidelines.

### Detailed Code Explanation

#### RAT Client Code (`rat_client.c`)

- **Includes and Defines**:
  - The necessary libraries for network communication, encryption, and system operations are included.
  - `AES_KEY` and `ICMP_PAYLOAD_SIZE` are defined for AES encryption and ICMP packet payload size.

- **Obfuscation Functions**:
  - `obfuscate_string` and `deobfuscate_string` use XOR and bitwise operations to obfuscate and deobfuscate strings.

- **Anti-Debugging Function**:
  - `anti_debug` uses inline assembly and checks for debugging environments. It attempts to detect if the process is being debugged and exits if so.

- **Shellcode Mutation Function**:
  - `mutate_shellcode` mutates the shellcode to make it harder to detect by signature-based defenses.

- **AES Encryption/Decryption Functions**:
  - `aes_encrypt` and `aes_decrypt` perform AES encryption and decryption using the OpenSSL library.

- **Checksum Function**:
  - `checksum` calculates the checksum for ICMP packets.

- **ICMP Functions**:
  - `send_ping` sends an ICMP ECHO request to a target IP with an encrypted message.
  - `receive_ping` listens for ICMP ECHO replies and prints the received message.

- **Persistence Setup**:
  - `setup_persistence` sets up persistence by copying the RAT executable to a hidden location and appending it to the bash profile.

- **Task Execution**:
  - `execute_task` performs encryption, decryption, and other tasks based on the command-line arguments.

- **Main Function**:
  - The main function handles anti-debugging, persistence setup, and executes tasks based on arguments. It also demonstrates shellcode mutation and sends an encrypted message using ICMP.

#### C2 Server Code (`c2_server.py`)

- **Encryption/Decryption Helpers**:
  - `pad` and `unpad` handle padding for AES encryption.
  - `encrypt` and `decrypt` perform AES encryption and decryption.

- **ICMP Socket Functions**:
  - `create_icmp_socket` creates a raw socket for ICMP communication.
  - `receive_icmp` listens for incoming ICMP packets and extracts the message.
  - `send_icmp` sends an ICMP reply with an encrypted message.
  - `calc_checksum` calculates the checksum for ICMP packets.

- **Main Function**:
  - The main function sets up the ICMP socket and enters a loop to receive and respond to ICMP packets. It decrypts incoming messages and sends encrypted responses.

#### Compile Script (`compile_rat.sh`)

- Compiles the RAT client C code using `gcc` and links OpenSSL libraries.

#### Run Server Script (`run_server.sh`)

- Starts the C2 server with necessary privileges.

#### Run RAT Client Script (`run_rat.sh`)

- Executes the RAT client with a provided command.

#### Automation Script (`automate.sh`)

- Automates the compilation of the RAT client, starts the C2 server, runs the RAT client with a test command, and then stops the server.

#### README.md

- Provides an overview of the project, setup instructions, and usage examples. It also includes a disclaimer regarding ethical use and proper authorization.

### Summary

This project demonstrates the implementation of a basic RAT client and a corresponding C2 server for secure communication using ICMP and AES encryption. The setup involves compiling the RAT client, running the C2 server, and executing commands on the client. The provided scripts streamline the process, ensuring a smooth workflow from setup to execution.
