# SHIELD — Linux SOC Analyzer

SHIELD is a Python-based Security Operations Center (SOC) log analysis tool built with Streamlit. It helps users investigate Linux logs, identify suspicious activity, extract Indicators of Compromise (IOCs), and generate security reports.

## Features

- Linux log analysis
- Suspicious activity and alert investigation
- Event Explorer
- IP address IOC extraction
- IP and domain reputation lookup using VirusTotal
- CSV and PDF report downloads
- Interactive Streamlit dashboard

## Tech Stack

- Python
- Streamlit
- Pandas
- VirusTotal API
- ReportLab

## Installation

```bash
git clone https://github.com/Ajay090120005/SHIELD-Linux-SOC-Analyzer.git
cd SHIELD-Linux-SOC-Analyzer

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
