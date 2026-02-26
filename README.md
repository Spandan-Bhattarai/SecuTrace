# 🛡️ SecuTrace - Free Threat Intelligence Platform

A privacy-focused threat intelligence aggregation platform that queries multiple security services to provide comprehensive analysis of IPs, domains, URLs, and file hashes.

![SecuTrace](https://img.shields.io/badge/SecuTrace-Active-success)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ Features

- **Multi-Source Intelligence**: Query 8+ threat intelligence sources simultaneously
- **Consensus-Based Scoring**: Aggregated threat level based on multiple platform agreement
- **Quick External Links**: One-click access to IBM X-Force, AbuseIPDB, and VirusTotal
- **Full Result Links**: Direct links to view detailed results on each platform
- **Privacy-Focused**: No data storage, no tracking, no accounts required
- **Modern Dark UI**: Clean, responsive interface with Bootstrap 5
- **Search History**: Local browser storage for recent lookups (clearable)
- **Free Services**: 3 services work without any API keys

## 📊 Integrated Services

| Service | Type | API Key Required | Full Result Link |
|---------|------|------------------|------------------|
| VirusTotal | Malware/Threat DB | Yes | ✅ |
| AbuseIPDB | IP Reputation | Yes | ✅ |
| Shodan | Infrastructure Recon | Yes | ✅ |
| AlienVault OTX | Threat Intelligence | Yes | ✅ |
| IPInfo | IP Geolocation | Yes | ✅ |
| URLhaus | Malicious URLs | Yes* | ✅ |
| ThreatFox | IOC Database | Yes* | ✅ |
| MalwareBazaar | Malware Samples | No | ✅ |

*URLhaus and ThreatFox share the same abuse.ch Auth-Key

### Quick External Search

Additional platforms accessible via quick search buttons:
- **IBM X-Force Exchange** - Threat intelligence platform
- **AbuseIPDB** - IP abuse reporting database
- **VirusTotal** - File and URL analysis

## 🚀 Quick Start

### 1. Clone & Install

```bash
cd soar
pip install -r requirements.txt
```

### 2. Configure API Keys

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API keys (see .env.example for instructions)
```

### 3. Run the Application

```bash
python app.py
```

### 4. Open in Browser

Navigate to `http://localhost:5000`

## 📖 Usage

1. Enter an IP address, domain, URL, or hash in the search box
2. Click **Analyze** to query all configured services
3. View the consensus-based threat score (HIGH/MEDIUM/LOW)
4. Use **Quick Search** buttons to check IBM X-Force, AbuseIPDB, or VirusTotal
5. Click **Full Result** on any source card to view details on that platform
6. Expand source cards for detailed information

### Supported Indicator Types

- **IP Addresses**: `8.8.8.8`, `192.168.1.1`
- **Domains**: `example.com`, `malware.domain.net`
- **URLs**: `https://example.com/path/to/file`
- **MD5 Hashes**: `d41d8cd98f00b204e9800998ecf8427e`
- **SHA1 Hashes**: `da39a3ee5e6b4b0d3255bfef95601890afd80709`
- **SHA256 Hashes**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

### Threat Scoring

SecuTrace uses consensus-based threat scoring:
- **HIGH RISK** (Red): 2+ sources report high threat level
- **MEDIUM RISK** (Blue): 2+ sources report medium, or 1 reports high
- **LOW RISK** (Green): Few or no concerning indicators

## 📁 Project Structure

```
soar/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── .env.example           # Environment template with instructions
├── .env                   # Your API keys (create this)
├── README.md              # This file
├── services/              # Threat intelligence clients
│   ├── __init__.py
│   ├── base_client.py     # Base class for clients
│   ├── threat_intel.py    # Main orchestration service
│   ├── virustotal.py      # VirusTotal integration
│   ├── abuseipdb.py       # AbuseIPDB integration
│   ├── shodan_client.py   # Shodan integration
│   ├── alienvault.py      # AlienVault OTX integration
│   ├── ipinfo.py          # IPInfo integration
│   ├── urlhaus.py         # URLhaus integration
│   ├── threatfox.py       # ThreatFox integration
│   └── malwarebazaar.py   # MalwareBazaar integration
└── templates/
    ├── index.html         # Main dashboard
    ├── about.html         # About page
    ├── privacy.html       # Privacy policy
    ├── cookies.html       # Cookie policy
    └── terms.html         # Terms of service
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/about` | GET | About SecuTrace |
| `/privacy` | GET | Privacy policy |
| `/cookies` | GET | Cookie policy |
| `/terms` | GET | Terms of service |
| `/api/lookup` | POST | Query all sources for an indicator |
| `/api/lookup/<source>` | POST | Query a specific source |
| `/api/sources` | GET | Get status of all configured sources |

### Example API Usage

```bash
# Full lookup
curl -X POST http://localhost:5000/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8"}'

# Single source lookup
curl -X POST http://localhost:5000/api/lookup/virustotal \
  -H "Content-Type: application/json" \
  -d '{"indicator": "evil.com"}'
```

## ⚙️ Configuration

Copy `.env.example` to `.env` and add your API keys. Each service has instructions in the example file.

### Minimum Setup (Free)

MalwareBazaar works without any API key.

### Recommended Setup

For best results, configure:
1. VirusTotal
2. AbuseIPDB
3. AlienVault OTX
4. THREATFOX_API_KEY (works for both URLhaus and ThreatFox)

## 🔒 Privacy

SecuTrace is built with privacy in mind:
- **No server-side data storage** - Queries processed in memory only
- **No accounts required** - Use anonymously
- **No tracking** - No analytics or behavioral profiling
- **Local history only** - Search history stored in browser localStorage
- **Clearable data** - One-click history deletion

## 🚀 Deployment

### Deploy to Render (Recommended)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

**One-click deployment:**
1. Fork this repository to your GitHub account
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect your forked repo
4. Render will auto-detect `render.yaml` and configure everything
5. Add your API keys in the Environment section
6. Deploy!

**Manual setup:**
1. New Web Service → Connect your repo
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `gunicorn app:app`
4. Add environment variables from `.env.example`

### Local Production

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 👨‍💻 Developer

**Spandan Bhattarai** (nadnap55)

- GitHub: [github.com/Spandan-Bhattarai](https://github.com/Spandan-Bhattarai)
- LinkedIn: [linkedin.com/in/spandan-bhattarai-113209180](https://www.linkedin.com/in/spandan-bhattarai-113209180/)
- Portfolio: [spandanb.com.np](https://spandanb.com.np)

## 📄 License

MIT License - feel free to use this for any purpose.

## ⚠️ Disclaimer

This tool is for educational and authorized security research purposes only. Ensure you have proper authorization before analyzing any indicators. The developers are not responsible for any misuse of this tool.

---

Made with ❤️ by [nadnap55](https://spandanb.com.np)
