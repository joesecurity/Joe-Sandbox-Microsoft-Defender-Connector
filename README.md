![Integration logo](img/integration.png)

# Joe-Sandbox-Microsoft-Defender-Addon
This script will enrich your Microsoft Defender Alerts with Joe Sandbox analysis data (Score, Detection, Threatname and link to the analysis).

## Requirements
- Python 3.x with required packages ([Required Packages](requirements.txt))
- Microsoft Defender for Endpoint
- Joe Sandbox Cloud Pro or Basic API key

## Installation & Setup

Clone the repository into your folder.

    git clone https://github.com/joesecurity/Joe-Sandbox-Microsoft-Defender-Addon.git

Install the requirements.

    pip install -r requirements.txt

## Microsoft Defender for Endpoint Setup

### Creating Application for API Access

- Open [https://portal.azure.com/](https://portal.azure.com) and `Microsoft Entra ID` service
- Click `App registrations`

![1](img/app.png)
