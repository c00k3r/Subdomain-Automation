# Passive Subdomain Recon Automation

A simple Bash automation script for **passive subdomain enumeration** using **Subfinder**. The script automates the process of discovering subdomains, removing duplicate entries, and saving the results in a structured output directory.

> **Disclaimer:** This project is intended for educational purposes and authorized security assessments only. Always obtain proper permission before performing reconnaissance on any target.

---

## Features

* Passive subdomain enumeration using **Subfinder**
* Automatic output directory creation
* Duplicate removal
* Total unique subdomain count
* Colorized terminal output
* Beginner-friendly Bash script

---

## Project Structure

```text
subdomain-recon/
│── recon.sh
│── README.md
│── .gitignore
└── output/
    └── .gitkeep
```

---

## Requirements

* Linux or WSL
* Bash
* Go (for installing Subfinder)
* Subfinder

### Install Subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Add Go binaries to your PATH if necessary:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify the installation:

```bash
subfinder -version
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/subdomain-recon.git
```

Move into the project directory:

```bash
cd subdomain-recon
```

Give execution permission to the script:

```bash
chmod +x recon.sh
```

---

## Usage

Run the script by providing a domain name:

```bash
./recon.sh example.com
```

---

## Example Output

```text
==============================================
      Passive Subdomain Recon Automation
==============================================

[+] Target: example.com
[+] Enumerating subdomains...

[✓] Enumeration Completed Successfully!
[✓] Total Unique Subdomains Found: 53
[✓] Results Saved To: output/subdomains.txt

==============================================
Done!
==============================================
```

---

## Output

The discovered subdomains are stored in:

```text
output/subdomains.txt
```

---

## Technologies Used

* Bash
* Subfinder
* Linux / WSL

---

## Future Improvements

* Live host detection
* HTTP status checking
* DNS resolution
* Screenshot automation
* JSON and CSV output support
* Logging
* Automatic report generation

---

## License

This project is licensed under the MIT License.

---

## Author

**Mrityunjay**

Cybersecurity Enthusiast | VAPT Intern | B.Tech CSE Student
