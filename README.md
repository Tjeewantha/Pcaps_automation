# Pcap_Automation.py

Pcap_authomation.py is a tool designed to automate the analysis of pcap (packet capture) files. It leverages the capabilities of the Python programming language to provide a user-friendly and efficient way to extract valuable information from pcap files.

## Features

- **Automated Analysis**: Pcap_authomation.py automates the process of analyzing pcap files, saving you time and effort.
- **Packet Inspection**: The tool allows you to inspect individual packets within the pcap file, providing detailed information such as source and destination IP addresses, protocols, tcp stream, udp stream.
- **Exporting Results**: Pcap_authomation.py allows you to export the analysis results to txt formatted file for further processing or reporting.
Note: While new features are including,

## Installation (Python 3.11.7)

1. Clone the repository or download the Pcap_authomation.py script.
2. Install the required dependencies by running the following command:

   pip install -r requirements.txt


## Usage

To use Pcap_authomation.py, follow these steps:

1. Open a terminal or command prompt.
2. Navigate to the directory where Pcap_authomation.py is located.
3. Run the following command to start the tool:

   python3 Pcap_authomation.py <pcap_file_path>
   
Replace `<pcap_file_path>` with the path to your pcap file.
Note: Outputs will save on directroy where Pcap_authomation.py has placed

## Examples

- Analyze a pcap file named "example.pcap":

  python3 Pcap_authomation.py example.pcap


