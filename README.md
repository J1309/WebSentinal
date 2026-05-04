---
title: WebSentinal
emoji: 🔒
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
---

# WebSentinal - Professional Web Application Vulnerability Scanner

A comprehensive web-based security tool that automates the detection of security flaws in web applications using OWASP ZAP integration.

## Features

- **User-Friendly Dashboard**: Clean web interface for easy vulnerability scanning
- **OWASP Top 10 Detection**: Specifically tuned for critical web application security risks
- **Automated Crawling**: Automatic navigation through target websites to map endpoints
- **Real-time Progress**: Asynchronous background scanning without UI freezing
- **Comprehensive Reporting**: Detailed HTML/PDF reports with risk categorization
- **Scan History**: Database storage of previous scans for tracking improvements
- **Authentication Support**: Capability to scan behind login pages

## Technologies Used

### Backend
- **Python**: Core programming language
- **Flask**: Lightweight web framework
- **SQLite**: Database for storing scan results
- **SQLAlchemy**: ORM for database interactions
- **Requests**: HTTP validation and header analysis

### Frontend
- **HTML5/CSS3**: Modern web standards
- **Bootstrap 5**: Responsive design framework
- **JavaScript**: Dynamic UI updates and AJAX
- **Chart.js**: Data visualization for vulnerability statistics

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd WebSentinal
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
```bash
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Run the application:
```bash
python app.py
```

6. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Start a Scan**: Enter a target URL on the homepage and click "Scan Now"
2. **Monitor Progress**: Track real-time scan progress on the dashboard
3. **View Results**: Access detailed vulnerability reports with risk categorization
4. **Generate Reports**: Export comprehensive PDF/HTML reports
5. **Review History**: Browse previous scan results and track security improvements

## Project Structure

```
WebSentinal/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── vulnscan.db           # SQLite database (created automatically)
└── templates/
    ├── index.html        # Homepage with scan interface
    ├── dashboard.html    # Main dashboard view
    ├── scan_results.html # Detailed scan results
    └── history.html      # Scan history page
```

## Database Schema

### Scan Table
- `id`: Unique scan identifier
- `target_url`: URL being scanned
- `status`: Current scan status (pending/scanning/completed/failed)
- `start_time`: Scan start timestamp
- `end_time`: Scan completion timestamp
- `progress`: Scan completion percentage
- `total_vulnerabilities`: Total vulnerabilities found
- `high_risk`: Count of high-risk vulnerabilities
- `medium_risk`: Count of medium-risk vulnerabilities
- `low_risk`: Count of low-risk vulnerabilities
- `informational`: Count of informational findings

### Vulnerability Table
- `id`: Unique vulnerability identifier
- `scan_id`: Reference to parent scan
- `name`: Vulnerability name
- `risk_level`: Risk classification (High/Medium/Low/Informational)
- `url`: Affected URL
- `parameter`: Vulnerable parameter
- `description`: Vulnerability description
- `solution`: Remediation advice
- `evidence`: Supporting evidence
- `created_at`: Timestamp

## Security Features

- URL validation and reachability checking
- Simulated vulnerability detection for demonstration
- Risk-based vulnerability categorization
- Detailed remediation guidance
- Secure session management

## Future Enhancements

- Integration with actual OWASP ZAP API
- Advanced authentication support (OAuth, JWT)
- Scheduled automated scanning
- Email notifications
- API endpoints for programmatic access
- Multi-user support with role-based access
- Advanced reporting with custom templates
- Integration with CI/CD pipelines

## License

This project is for educational and demonstration purposes.

## Contributing

Feel free to submit issues and enhancement requests!

## Disclaimer

This tool is designed for authorized security testing only. Always obtain proper permission before scanning any website or application.