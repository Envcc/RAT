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

### English
1. Hacking toolkit
2. Cybersecurity
3. Remote Access Tool (RAT)
4. Command and Control (C2)
5. ICMP communication
6. Stealth communication
7. AES encryption
8. Anti-debugging techniques
9. Polymorphic shellcode
10. Dynamic code loading
11. Penetration testing
12. Network security
13. Cyber defense
14. Malware analysis
15. Ethical hacking
16. Exploit development
17. Security research
18. Cyber threat
19. System security
20. Vulnerability assessment

### Spanish (Español)
1. Kit de herramientas de hacking
2. Ciberseguridad
3. Herramienta de acceso remoto
4. Comando y control (C2)
5. Comunicación ICMP
6. Comunicación encubierta
7. Cifrado AES
8. Técnicas anti-debugging
9. Shellcode polimórfico
10. Carga de código dinámico
11. Pruebas de penetración
12. Seguridad de red
13. Defensa cibernética
14. Análisis de malware
15. Hacking ético
16. Desarrollo de exploits
17. Investigación en seguridad
18. Amenaza cibernética
19. Seguridad del sistema
20. Evaluación de vulnerabilidades

### French (Français)
1. Kit d'outils de hacking
2. Cybersécurité
3. Outil d'accès à distance
4. Commande et contrôle (C2)
5. Communication ICMP
6. Communication furtive
7. Chiffrement AES
8. Techniques anti-debugging
9. Shellcode polymorphe
10. Chargement de code dynamique
11. Tests de pénétration
12. Sécurité réseau
13. Défense cybernétique
14. Analyse de malware
15. Hacking éthique
16. Développement d'exploits
17. Recherche en sécurité
18. Menace cybernétique
19. Sécurité système
20. Évaluation des vulnérabilités

### German (Deutsch)
1. Hacking-Toolkit
2. Cybersicherheit
3. Remote Access Tool (RAT)
4. Kommando und Kontrolle (C2)
5. ICMP-Kommunikation
6. Stealth-Kommunikation
7. AES-Verschlüsselung
8. Anti-Debugging-Techniken
9. Polymorpher Shellcode
10. Dynamische Code-Ladung
11. Penetrationstest
12. Netzwerksicherheit
13. Cyber-Verteidigung
14. Malware-Analyse
15. Ethisches Hacking
16. Exploit-Entwicklung
17. Sicherheitsforschung
18. Cyber-Bedrohung
19. Systemsicherheit
20. Schwachstellenbewertung

### Chinese (Simplified, 中文)
1. 黑客工具包
2. 网络安全
3. 远程访问工具
4. 指挥和控制 (C2)
5. ICMP 通信
6. 隐秘通信
7. AES 加密
8. 反调试技术
9. 多态 shellcode
10. 动态代码加载
11. 渗透测试
12. 网络安全
13. 网络防御
14. 恶意软件分析
15. 伦理黑客
16. 利用开发
17. 安全研究
18. 网络威胁
19. 系统安全
20. 漏洞评估

### Russian (Русский)
1. Набор инструментов для хакеров
2. Кибербезопасность
3. Инструмент удаленного доступа
4. Команда и контроль (C2)
5. ICMP связь
6. Скрытая связь
7. AES шифрование
8. Техники анти-отладки
9. Полиморфный shellcode
10. Динамическая загрузка кода
11. Тестирование на проникновение
12. Сетевая безопасность
13. Киберзащита
14. Анализ вредоносного ПО
15. Этический хакинг
16. Разработка эксплойтов
17. Исследование безопасности
18. Киберугроза
19. Безопасность системы
20. Оценка уязвимостей

### Japanese (日本語)
1. ハッキングツールキット
2. サイバーセキュリティ
3. リモートアクセスツール
4. 指揮統制 (C2)
5. ICMP 通信
6. ステルス通信
7. AES 暗号化
8. 逆デバッグ技術
9. 多相 shellcode
10. 動的コードローディング
11. 侵入テスト
12. ネットワークセキュリティ
13. サイバー防御
14. マルウェア分析
15. 倫理的ハッキング
16. エクスプロイト開発
17. セキュリティ研究
18. サイバー脅威
19. システムセキュリティ
20. 脆弱性評価

### Korean (한국어)
1. 해킹 도구 키트
2. 사이버 보안
3. 원격 액세스 도구
4. 지휘 통제 (C2)
5. ICMP 통신
6. 스텔스 통신
7. AES 암호화
8. 안티 디버깅 기술
9. 다형성 셸코드
10. 동적 코드 로드
11. 침투 테스트
12. 네트워크 보안
13. 사이버 방어
14. 악성 코드 분석
15. 윤리적 해킹
16. 익스플로잇 개발
17. 보안 연구
18. 사이버 위협
19. 시스템 보안
20. 취약점 평가

### Portuguese (Português)
1. Kit de ferramentas de hacking
2. Cibersegurança
3. Ferramenta de acesso remoto
4. Comando e controle (C2)
5. Comunicação ICMP
6. Comunicação furtiva
7. Criptografia AES
8. Técnicas anti-debugging
9. Shellcode polimórfico
10. Carregamento de código dinâmico
11. Teste de penetração
12. Segurança de rede
13. Defesa cibernética
14. Análise de malware
15. Hacking ético
16. Desenvolvimento de exploits
17. Pesquisa de segurança
18. Ameaça cibernética
19. Segurança do sistema
20. Avaliação de vulnerabilidades

### Italian (Italiano)
1. Kit di strumenti per hacking
2. Sicurezza informatica
3. Strumento di accesso remoto
4. Comando e controllo (C2)
5. Comunicazione ICMP
6. Comunicazione stealth
7. Crittografia AES
8. Tecniche anti-debugging
9. Shellcode polimorfico
10. Caricamento dinamico del codice
11. Test di penetrazione
12. Sicurezza di rete
13. Difesa informatica
14. Analisi di malware
15. Hacking etico
16. Sviluppo di exploit
17. Ricerca sulla sicurezza
18. Minaccia informatica
19. Sicurezza del sistema
20. Valutazione delle vulnerabilità

Sure, here are detailed sections to add to your README to improve SEO:

### Introduction
```markdown
# RAT Client and C2 Server - Ultimate Covert Command & Control Toolkit 🚀

Welcome to the ultimate covert Command & Control (C2) toolkit! This repository is a comprehensive suite for those who are keen on mastering the art of stealthy communication and control over remote systems. Designed with advanced techniques in mind, this toolkit provides everything a sophisticated hacker needs to establish an undetectable command channel between the client and server.
```

### Features
```markdown
## Features

### 🛡️ Advanced Anti-Debugging and Anti-VM Techniques
Bypass conventional debugging attempts with robust anti-debugging mechanisms. Detect and evade virtual machine environments to ensure your client runs undetected on genuine targets.

### 🔒 Strong AES Encryption
Secure your communications with AES encryption, ensuring that all data transferred between the client and server is completely secure and unreadable to prying eyes.

### 📨 Stealthy ICMP Communication
Use ICMP packets for covert communication. Avoid detection by standard network monitoring tools and firewalls with this sophisticated method of data transfer.

### 🎭 Polymorphic Shellcode Mutation
Evade signature-based detection systems by continuously altering the shellcode. This polymorphic approach ensures that your payload remains undetected and effective.

### 💡 Dynamic Code Loading
Load and execute code dynamically from files, allowing for easy updates and expansions of functionality without the need to redeploy the client.

### 🛠️ Command Execution
Execute arbitrary shell commands received from the C2 server, giving you full control over the remote system.
```

### Installation Instructions
```markdown
## Installation

### Prerequisites
- **Operating System**: Linux (root privileges required)
- **Dependencies**: OpenSSL libraries for encryption

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
```

### Usage Examples
```markdown
## Usage Examples

### Executing a Shell Command
To execute a shell command on the client machine, run the following command on the C2 server:
```python
# Example command to send 'ls -la' to the client
shell_command = "ls -la"
encrypted_command = encrypt(shell_command.encode('utf-8'))
send_icmp(sock, addr[0], encrypted_command)
```

### Encrypting Data
To encrypt data using the AES encryption method:
```c
unsigned char plaintext[64] = "Sensitive data";
unsigned char ciphertext[64];
aes_encrypt(plaintext, AES_KEY, ciphertext);
printf("Encrypted: %s\n", ciphertext);
```

### Decrypting Data
To decrypt data received from the C2 server:
```c
unsigned char ciphertext[64] = "EncryptedData";
unsigned char plaintext[64];
aes_decrypt(ciphertext, AES_KEY, plaintext);
printf("Decrypted: %s\n", plaintext);
```
```

### FAQ
```markdown
## FAQ

### What is a Remote Access Tool (RAT)?
A Remote Access Tool (RAT) is a type of software that allows a remote operator to control a system as if they have physical access to it.

### Is this toolkit legal to use?
This toolkit is intended for educational purposes and authorized security testing only. Misuse of this software can result in severe legal consequences. Always obtain proper authorization before using it on any network or system.

### How does the anti-debugging technique work?
The anti-debugging techniques used in this toolkit involve various methods like inline assembly to detect and prevent debugging attempts, as well as checks for parent process ID and use of ptrace.

### How does ICMP communication help in stealth?
ICMP communication is often used in network diagnostics (like ping). Using ICMP packets for data transfer can help evade detection by standard network monitoring tools and firewalls.
```

### Contributing
```markdown
## Contributing

We welcome contributions from the community! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

Please ensure your code adheres to the existing coding style and includes relevant tests.
```

### License
```markdown
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```

### Contact and Support
```markdown
## Contact and Support

For support, questions, or suggestions, please open an issue or contact us directly.

**Email**: support@cybersec-toolkit.com
```

### Social Media Links
```markdown
## Follow Us

Stay updated with the latest features and news:

- [Twitter](https://twitter.com/cybersec_toolkit)
- [LinkedIn](https://www.linkedin.com/company/cybersec-toolkit)
- [YouTube](https://www.youtube.com/channel/UCyberSecToolkit)
- [Facebook](https://www.facebook.com/cybersec-toolkit)
```

By including these sections and optimizing for keywords, you will enhance the visibility of your repository on search engines and attract a global audience.
