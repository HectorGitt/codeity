# 🔒 CodeSec Scanner

A comprehensive full-stack security vulnerability scanner built with FastAPI that analyzes codebases for security breaches, vulnerabilities, and malware intentions. Supports both file uploads and GitHub repository scanning.

## ✨ Features

### 🛡️ Security Scanners

-   **Bandit** - Python-specific security linter for common security issues
-   **Safety** - Dependency vulnerability checker for Python packages
-   **Semgrep** - Multi-language static analysis security scanner

### 📁 Input Methods

-   **File Upload** - Upload individual files or archives (.zip, .tar.gz, .tar)
-   **GitHub Integration** - Directly scan public GitHub repositories by URL

### 🖥️ User Interface

-   **Modern Web Interface** - Responsive, intuitive web UI
-   **Real-time Progress** - Live scan status updates
-   **Detailed Results** - Comprehensive vulnerability reports with severity levels
-   **Interactive Dashboard** - Visual summary of security findings

### 🔧 Technical Features

-   **Asynchronous Processing** - Non-blocking scan execution
-   **Background Tasks** - Queued scan processing
-   **RESTful API** - Complete API for programmatic access
-   **File Type Support** - Python, JavaScript, Java, C/C++, and more
-   **Archive Extraction** - Automatic extraction of compressed files

## 🚀 Quick Start

### Prerequisites

-   Python 3.8 or higher
-   Git (for cloning repositories)

### Installation

1. **Clone the repository**

    ```bash
    git clone <your-repo-url>
    cd codeity
    ```

2. **Create virtual environment**

    ```bash
    python -m venv venv
    ```

3. **Activate virtual environment**

    **Windows:**

    ```bash
    venv\Scripts\activate
    ```

    **Linux/macOS:**

    ```bash
    source venv/bin/activate
    ```

4. **Install dependencies**

    ```bash
    pip install -r requirements.txt
    ```

5. **Start the application**

    **Windows:**

    ```bash
    start.bat
    ```

    **Linux/macOS:**

    ```bash
    chmod +x start.sh
    ./start.sh
    ```

6. **Access the application**
    - Web Interface: http://localhost:8000
    - API Documentation: http://localhost:8000/docs

## 📖 Usage Guide

### Web Interface

1. **Upload Files**

    - Select individual files or compressed archives
    - Choose which security scanners to run
    - Click "Scan Uploaded Files"

2. **Scan GitHub Repository**

    - Enter a public GitHub repository URL
    - Select desired security scanners
    - Click "Scan GitHub Repository"

3. **View Results**
    - Monitor real-time scan progress
    - Review vulnerability summary dashboard
    - Examine detailed findings with file locations and recommendations

### API Usage

#### Start a File Upload Scan

```bash
curl -X POST "http://localhost:8000/scan/upload" \
  -F "files=@your_file.py" \
  -F "scan_types=bandit" \
  -F "scan_types=safety"
```

#### Start a GitHub Repository Scan

```bash
curl -X POST "http://localhost:8000/scan/github" \
  -H "Content-Type: application/json" \
  -d '{
    "github_url": "https://github.com/user/repo",
    "scan_types": ["bandit", "safety", "semgrep"]
  }'
```

#### Check Scan Status

```bash
curl "http://localhost:8000/scan/{scan_id}/status"
```

#### Get Scan Results

```bash
curl "http://localhost:8000/scan/{scan_id}/results"
```

## 🔍 Security Scanners Details

### Bandit

-   **Purpose**: Python-specific security analysis
-   **Detects**: Hard-coded passwords, SQL injection risks, unsafe functions
-   **Output**: JSON format with severity levels and code snippets

### Safety

-   **Purpose**: Dependency vulnerability checking
-   **Detects**: Known vulnerabilities in Python packages
-   **Output**: CVE information and upgrade recommendations

### Semgrep

-   **Purpose**: Multi-language static analysis
-   **Detects**: Security patterns across various programming languages
-   **Output**: OWASP Top 10 and custom security rules

## 📊 Vulnerability Severity Levels

-   **🔴 HIGH** - Critical security vulnerabilities requiring immediate attention
-   **🟡 MEDIUM** - Important security issues that should be addressed
-   **🟢 LOW** - Minor security concerns or best practice violations

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=False

# Security Settings
SECRET_KEY=your-secret-key-here
MAX_FILE_SIZE=100MB
ALLOWED_EXTENSIONS=.py,.js,.java,.cpp,.c,.zip,.tar.gz,.tar,.php

# Scanner Configuration
ENABLE_BANDIT=true
ENABLE_SAFETY=true
ENABLE_SEMGREP=true

# GitHub Integration
GITHUB_TOKEN=your-github-token (optional, for private repos)
```

### Custom Scanner Rules

You can extend the scanners with custom rules:

1. **Bandit**: Create custom `.bandit` configuration file
2. **Semgrep**: Add custom rules in `semgrep-rules/` directory
3. **Safety**: Configure with `safety-config.json`

## 🏗️ Architecture

```
CodeSec Scanner
├── main.py              # FastAPI application
├── requirements.txt     # Python dependencies
├── static/             # Static web assets
├── templates/          # HTML templates
├── logs/              # Application logs
├── start.sh           # Linux/macOS startup script
└── start.bat          # Windows startup script
```

### Key Components

1. **FastAPI Backend** - Handles API requests and scan orchestration
2. **Background Tasks** - Asynchronous scan processing
3. **Security Scanners** - Integrated Bandit, Safety, and Semgrep
4. **Web Interface** - Modern, responsive frontend
5. **File Processing** - Upload handling and archive extraction

## 🔐 Security Considerations

### Input Validation

-   File type validation
-   Archive size limits
-   URL validation for GitHub repositories

### Sandboxing

-   Temporary directories for scan isolation
-   Automatic cleanup after scan completion
-   Process isolation for security scanners

### Data Privacy

-   No persistent storage of uploaded files
-   Scan results stored temporarily in memory
-   Option to clear results after download

## 🚀 Deployment

### Production Deployment

1. **Install Production WSGI Server**

    ```bash
    pip install gunicorn
    ```

2. **Run with Gunicorn**

    ```bash
    gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
    ```

3. **Docker Deployment**
    ```dockerfile
    FROM python:3.9-slim
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install -r requirements.txt
    COPY . .
    EXPOSE 8000
    CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
    ```

### Performance Optimization

-   Use Redis for scan result caching
-   Implement task queues with Celery
-   Add database for persistent storage
-   Configure load balancing for high traffic

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Commit your changes: `git commit -m 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

**Scanner not found error:**

```bash
# Install missing scanner
pip install bandit safety semgrep
```

**Permission denied on temporary files:**

```bash
# Fix permissions
chmod 755 /tmp
```

**GitHub clone fails:**

-   Ensure the repository is public
-   Check internet connectivity
-   Verify the GitHub URL format

### Getting Help

-   📧 Create an issue on GitHub
-   💬 Check existing issues and discussions
-   📖 Review the API documentation at `/docs`

## 🔄 Changelog

### v1.0.0

-   Initial release with Bandit, Safety, and Semgrep integration
-   Web interface for file uploads and GitHub scanning
-   RESTful API with real-time status updates
-   Support for multiple file formats and archives

---

**Built with ❤️ using FastAPI and modern web technologies**
