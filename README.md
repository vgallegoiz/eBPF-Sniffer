# eBPF-Sniffer


This repository contains a network sniffer developed in eBPF that captures network packets and stores them in a MySQL database. This project is useful for analyzing network traffic and conducting security audits.

## Features

- Real-time packet capture.
- Storage of relevant packet data (IP addresses, ports, protocols, etc.) in a MySQL database.
- Compatible with multiple network protocols.

## Prerequisites

Before running this project, make sure you have the following components installed:

1. **Python 3.x**
2. **Python Libraries:**
   - `scapy` for packet capture.
   - `mysql-connector-python` or `pymysql` for interacting with the MySQL database.
3. **MySQL Server:**
   - A database configured to store the packet data.

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/network-sniffer.git
   cd network-sniffer
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure the MySQL database:
   - Create a database to store the data.
   - Import the schema provided in the `database.sql` file.

## Configuration

Edit the `.env` file to include your MySQL database credentials and other configuration parameters:

```python
DB_HOST = 'localhost'
DB_USER = 'your_user'
DB_PASSWORD = 'your_password'
DB_NAME = 'your_database_name'
```
## Usage

Run the sniffer with the following command:

```bash
python sniffer.py
```

## Contributions

If you would like to contribute to this project:

1. Fork the repository.
2. Create a branch for your feature or bug fix:

   ```bash
   git checkout -b my-new-feature
   ```

3. Commit your changes and open a Pull Request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Credits

Developed by
- Paul Schwoertzig
- Marcel Peña
- Lluís Noguera
- Marcel Sarraseca
- Víctor Gallego
