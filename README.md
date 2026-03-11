# # Python Port Scanner

A fast multi-threaded TCP port scanner written in Python for cybersecurity learning and network analysis.

---

## Features

- Multi-threaded port scanning for faster performance
- Custom port range scanning
- Detection of common services (HTTP, SSH, FTP, etc.)
- Interactive CLI mode
- Real-time scan progress
- Clean and readable scan summary
- Lightweight and easy to run

---

## Installation

Clone the repository:

git clone https://github.com/yourusername/port-scanner.git

cd port-scanner

Run the script:

python PortScanner.py

---

## Usage

Scan a host:

python PortScanner.py -H example.com

Scan specific ports:

python PortScanner.py -H example.com -p 22,80,443

Run interactive mode:

python PortScanner.py

---

## Example Output

PORT     STATE   SERVICE  
22       OPEN    SSH  
80       OPEN    HTTP  
443      OPEN    HTTPS  

Scan completed successfully.

---

## Technologies Used

- Python
- Socket Programming
- Multithreading
- Queue
- Networking fundamentals

---

## Learning Goals

This project was built to better understand:

- How TCP port scanning works
- Network communication using Python sockets
- Multithreading for performance
- Basic cybersecurity reconnaissance techniques

---

## Disclaimer

This project is intended for **educational and ethical testing purposes only**.  
Do not scan systems or networks without proper authorization.

---

## Author

Developed by **Tariq H. Almlaki**