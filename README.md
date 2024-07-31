
# IOC Lookup Tool

## Project Description

This project is a tool designed to query Indicators of Compromise (IOC) such as IP addresses, domains, URLs, and file hashes across different Threat Intelligence (TI) sources. The program determines the type of IOC provided via command-line arguments and performs the appropriate queries using APIs, returning the results to the user.

## Features
- Query IP addresses via AbuseIPDB API.
- Query IP addresses, domains, URLs, and file hashes via VirusTotal API.
- Automatically determine the type of IOC (IP, domain, URL, hash).
- Easy to use with command-line arguments.
- Easily extendable to include additional TI sources.

## Technologies Used
- Python 3
- `requests` library (for making HTTP requests)
- JSON (for processing API responses)
- `argparse` (for handling command-line arguments)

## Installation Steps

1. **Install Requirements:**
   - This project runs on Python 3. After cloning the project, install the necessary Python libraries by running:
     ```sh
     pip install requests
     ```

2. **Update API Keys:**
   - Update the `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` variables at the top of the code with your own API keys.

3. **Running the Code:**
   - To start the IOC lookup process, run the following command:
     ```sh
     python main.py [IOC]
     ```
   - Replace `[IOC]` with the IP address, domain, URL, or file hash you want to query.

   **Example Usages:**
   - To query an IP address:
     ```sh
     python main.py 118.25.6.39
     ```
   - To query a domain:
     ```sh
     python main.py example.com
     ```
   - To query a URL:
     ```sh
     python main.py http://example.com
     ```
   - To query a hash:
     ```sh
     python main.py d41d8cd98f00b204e9800998ecf8427e
     ```

## IOC Types and Supported Sources
- **IP Address:** AbuseIPDB, VirusTotal
- **Domain:** VirusTotal
- **URL:** VirusTotal
- **Hash (MD5, SHA-1, SHA-256):** VirusTotal

## Potential Enhancements
- Additional TI sources can be added by defining relevant functions.
- Error handling and management for API calls can be implemented.
- User interface or reporting functions can be added.

## Support and Contact
If you have any questions or would like to contribute, please contact at [kilicbartu@gmail.com](mailto:kilicbartu@gmail.com).