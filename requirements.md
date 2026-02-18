# Network Scanner Requirements

## Functional Requirements

### Scan Modes

The scanner must allow the user to scan:

* A complete subnet
* A single specific host

---

### Host Information Detection

For each discovered host, the scanner must detect:

* IP address
* MAC address
* Open ports
* Service associated with each open port
* Hostname
* Operating system

---

### Output Requirements

* Output must be well-structured
* Output must be easy to read
* Output must be neatly formatted (e.g., using formatted strings)

---

## Code Requirements

### Nmap Usage Restrictions

The Python nmap module may **not** be used, except for:

* Service detection
* Operating system detection

All other functionality must be implemented manually.

---

### Code Quality

* Code must be clearly written
* Must include clear comments
* Must include docstrings
* Preferred language: English

---

### Coding Standards

* Code must follow **PEP 8** standards

---

## Bonus Requirements (Optional)

### CLI Interface

* Scanner can be run from the command line
* All scan options configurable via flags

---

### Flexible Targeting

User can scan:

* Different subnets
* Individual hosts
* Multiple targets via CLI

---

### Output Enhancements

* Use color to improve readability

---

### Runtime Feedback

* Display progress during scanning
* Show summary metrics after scan (e.g., time, hosts found, open ports)

---

## Usage Notes

* Run the code from a terminal.
* See the guide printed by the program for available commands and options.
* You can use the terminal to execute commands and pass flags to the scanner.
