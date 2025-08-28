from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import aiofiles
import asyncio
import os
import tempfile
import shutil
import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, HttpUrl
import git
import zipfile
import tarfile
from urllib.parse import urlparse
from pathlib import Path

# Initialize FastAPI app
app = FastAPI(
    title="CodeSec Scanner",
    description="A comprehensive security vulnerability scanner for codebases",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up static files and templates
static_dir = "static"
templates_dir = "templates"

# Create directories if they don't exist
os.makedirs(static_dir, exist_ok=True)
os.makedirs(templates_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# In-memory storage for scan results (in production, use a database)
scan_results = {}
scan_status = {}


# Pydantic models
class ScanRequest(BaseModel):
    github_url: Optional[HttpUrl] = None
    scan_types: List[str] = ["bandit", "safety", "semgrep"]


class CodeScanRequest(BaseModel):
    code_content: str
    language: str
    scan_types: List[str] = ["bandit", "semgrep"]


class ScanResult(BaseModel):
    scan_id: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[Dict[str, Any]] = None
    errors: List[str] = []


class VulnerabilityInfo(BaseModel):
    tool: str
    severity: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


# Helper functions
def get_scanner_executable(scanner_name: str) -> str:
    """Get the path to a scanner executable"""
    if scanner_name == "bandit":
        # Use virtual environment Python for bandit
        if os.name == "nt":  # Windows
            venv_python = os.path.join(os.getcwd(), "venv", "Scripts", "python.exe")
            if os.path.exists(venv_python):
                return venv_python
        return "python"

    if os.name == "nt":  # Windows
        venv_scripts = os.path.join(os.getcwd(), "venv", "Scripts")
        exe_path = os.path.join(venv_scripts, f"{scanner_name}.exe")
        if os.path.exists(exe_path):
            return exe_path

    # Fallback to system PATH
    return scanner_name


async def run_command(
    command: List[str], cwd: Optional[str] = None, timeout: int = 300
) -> Dict[str, Any]:
    """Run a shell command and return the result"""
    try:
        print(f"Executing command: {' '.join(command)}")
        print(f"Working directory: {cwd}")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timeout after {timeout} seconds",
            }

        result = {
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="ignore"),
            "stderr": stderr.decode("utf-8", errors="ignore"),
        }

        print(
            f"Command result: returncode={result['returncode']}, stdout_length={len(result['stdout'])}, stderr_length={len(result['stderr'])}"
        )

        return result

    except FileNotFoundError as e:
        error_msg = f"Command not found: {command[0]} - {str(e)}"
        print(f"FileNotFoundError: {error_msg}")
        return {"returncode": -1, "stdout": "", "stderr": error_msg}
    except PermissionError as e:
        error_msg = f"Permission denied: {str(e)}"
        print(f"PermissionError: {error_msg}")
        return {"returncode": -1, "stdout": "", "stderr": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"Exception: {error_msg}")
        return {"returncode": -1, "stdout": "", "stderr": error_msg}


async def clone_repository(github_url: str, target_dir: str) -> bool:
    """Clone a GitHub repository to target directory"""
    try:
        # Parse the GitHub URL
        parsed_url = urlparse(str(github_url))
        if "github.com" not in parsed_url.netloc:
            raise ValueError("Only GitHub URLs are supported")

        # Clone the repository
        git.Repo.clone_from(str(github_url), target_dir)
        return True
    except Exception as e:
        print(f"Error cloning repository: {e}")
        return False


async def extract_archive(file_path: str, target_dir: str) -> bool:
    """Extract uploaded archive to target directory"""
    try:
        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(target_dir)
        elif file_path.endswith((".tar.gz", ".tgz")):
            with tarfile.open(file_path, "r:gz") as tar_ref:
                tar_ref.extractall(target_dir)
        elif file_path.endswith(".tar"):
            with tarfile.open(file_path, "r") as tar_ref:
                tar_ref.extractall(target_dir)
        else:
            # For individual files, copy to target directory
            shutil.copy2(file_path, target_dir)
        return True
    except Exception as e:
        print(f"Error extracting archive: {e}")
        return False


async def test_scanner_availability(scanner_name: str) -> bool:
    """Test if a scanner is available and working"""
    try:
        if scanner_name == "bandit":
            bandit_exe = get_scanner_executable("bandit")
            cmd = [bandit_exe, "-m", "bandit", "--version"]
            result = await run_command(cmd, timeout=30)
            return result["returncode"] == 0
        # Add other scanners here if needed
        return False
    except Exception as e:
        print(f"Error testing {scanner_name} availability: {e}")
        return False


async def run_bandit_scan(scan_dir: str) -> Dict[str, Any]:
    """Run Bandit security scanner"""
    try:
        bandit_exe = get_scanner_executable("bandit")
        # Always use Python module approach for bandit
        cmd = [bandit_exe, "-m", "bandit", "-r", scan_dir, "-f", "json"]
        result = await run_command(cmd)
        print(f"Bandit command: {' '.join(cmd)}")
        print(f"Bandit result: {result}")

        if result["returncode"] == 0 or result["stdout"]:
            try:
                bandit_results = json.loads(result["stdout"])
                return {
                    "tool": "bandit",
                    "status": "success",
                    "results": bandit_results,
                    "vulnerabilities": parse_bandit_results(bandit_results),
                }
            except json.JSONDecodeError:
                return {
                    "tool": "bandit",
                    "status": "error",
                    "error": "Failed to parse JSON output",
                    "raw_output": result["stdout"],
                }
        else:
            return {
                "tool": "bandit",
                "status": "error",
                "error": result["stderr"] or "Bandit scan failed",
            }
    except Exception as e:
        return {"tool": "bandit", "status": "error", "error": str(e)}


async def run_safety_scan(scan_dir: str) -> Dict[str, Any]:
    """Run Safety dependency checker"""
    try:
        # Look for requirements.txt or setup.py
        requirements_files = []
        for root, dirs, files in os.walk(scan_dir):
            for file in files:
                if file in [
                    "requirements.txt",
                    "setup.py",
                    "Pipfile",
                    "pyproject.toml",
                ]:
                    requirements_files.append(os.path.join(root, file))

        if not requirements_files:
            return {
                "tool": "safety",
                "status": "skipped",
                "message": "No dependency files found",
            }

        cmd = [get_scanner_executable("safety"), "check", "--json"]
        result = await run_command(cmd, cwd=scan_dir)

        try:
            safety_results = json.loads(result["stdout"]) if result["stdout"] else []
            return {
                "tool": "safety",
                "status": "success",
                "results": safety_results,
                "vulnerabilities": parse_safety_results(safety_results),
            }
        except json.JSONDecodeError:
            return {
                "tool": "safety",
                "status": "success",
                "results": [],
                "vulnerabilities": [],
                "message": "No vulnerabilities found or no dependencies to check",
            }
    except Exception as e:
        return {"tool": "safety", "status": "error", "error": str(e)}


async def run_semgrep_scan(scan_dir: str) -> Dict[str, Any]:
    """Run Semgrep static analysis"""
    try:
        cmd = [get_scanner_executable("semgrep"), "--config=auto", "--json", scan_dir]
        result = await run_command(cmd)
        print(result)

        if result["returncode"] == 0 or result["stdout"]:
            try:
                semgrep_results = json.loads(result["stdout"])
                return {
                    "tool": "semgrep",
                    "status": "success",
                    "results": semgrep_results,
                    "vulnerabilities": parse_semgrep_results(semgrep_results),
                }
            except json.JSONDecodeError:
                return {
                    "tool": "semgrep",
                    "status": "error",
                    "error": "Failed to parse JSON output",
                    "raw_output": result["stdout"],
                }
        else:
            return {
                "tool": "semgrep",
                "status": "error",
                "error": result["stderr"] or "Semgrep scan failed",
            }
    except Exception as e:
        return {"tool": "semgrep", "status": "error", "error": str(e)}


def parse_bandit_results(results: Dict) -> List[VulnerabilityInfo]:
    """Parse Bandit results into standardized format"""
    vulnerabilities = []

    for issue in results.get("results", []):
        vuln = VulnerabilityInfo(
            tool="bandit",
            severity=issue.get("issue_severity", "UNKNOWN"),
            description=issue.get("issue_text", ""),
            file_path=issue.get("filename", ""),
            line_number=issue.get("line_number"),
            code_snippet=issue.get("code", ""),
            recommendation=issue.get("issue_text", ""),
        )
        vulnerabilities.append(vuln)

    return vulnerabilities


def parse_safety_results(results: List) -> List[VulnerabilityInfo]:
    """Parse Safety results into standardized format"""
    vulnerabilities = []

    for issue in results:
        vuln = VulnerabilityInfo(
            tool="safety",
            severity="HIGH",  # Safety issues are typically high severity
            description=f"Vulnerable dependency: {issue.get('package_name', '')} {issue.get('analyzed_version', '')}",
            file_path="requirements.txt",
            recommendation=f"Upgrade to version {issue.get('vulnerable_spec', '')}",
        )
        vulnerabilities.append(vuln)

    return vulnerabilities


def parse_semgrep_results(results: Dict) -> List[VulnerabilityInfo]:
    """Parse Semgrep results into standardized format"""
    vulnerabilities = []

    for result in results.get("results", []):
        # Extract code snippet using the helper function
        code_snippet = extract_code_snippet(
            result.get("path", ""),
            result.get("start", {}).get("line", 0),
            result.get("end", {}).get("line", 0),
        )
        vuln = VulnerabilityInfo(
            tool="semgrep",
            severity=result.get("extra", {}).get("severity", "UNKNOWN"),
            description=result.get("extra", {}).get("message", ""),
            file_path=result.get("path", ""),
            line_number=result.get("start", {}).get("line"),
            code_snippet=code_snippet,
            recommendation=result.get("extra", {}).get("fix", ""),
        )
        vulnerabilities.append(vuln)

    return vulnerabilities


def extract_code_snippet(file_path: str, start_line: int, end_line: int) -> str:
    """Extract code snippet from a file given start and end lines."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            snippet = "".join(lines[start_line - 1 : end_line])
            return snippet
    except Exception as e:
        print(f"Error extracting code snippet: {e}")
        return "Error extracting code snippet"


async def perform_security_scan(scan_id: str, scan_dir: str, scan_types: List[str]):
    """Perform the actual security scan"""
    try:
        scan_status[scan_id] = "running"
        results = {}
        all_vulnerabilities = []

        # Run selected scanners
        if "bandit" in scan_types:
            scan_status[scan_id] = "running_bandit"
            bandit_result = await run_bandit_scan(scan_dir)
            results["bandit"] = bandit_result
            if "vulnerabilities" in bandit_result:
                all_vulnerabilities.extend(bandit_result["vulnerabilities"])

        if "safety" in scan_types:
            scan_status[scan_id] = "running_safety"
            safety_result = await run_safety_scan(scan_dir)
            results["safety"] = safety_result
            if "vulnerabilities" in safety_result:
                all_vulnerabilities.extend(safety_result["vulnerabilities"])

        if "semgrep" in scan_types:
            scan_status[scan_id] = "running_semgrep"
            semgrep_result = await run_semgrep_scan(scan_dir)
            print(semgrep_result)
            results["semgrep"] = semgrep_result
            if "vulnerabilities" in semgrep_result:
                all_vulnerabilities.extend(semgrep_result["vulnerabilities"])

        # Generate summary
        summary = {
            "total_vulnerabilities": len(all_vulnerabilities),
            "high_severity": len(
                [v for v in all_vulnerabilities if v.severity.upper() == "HIGH"]
            ),
            "medium_severity": len(
                [v for v in all_vulnerabilities if v.severity.upper() == "MEDIUM"]
            ),
            "low_severity": len(
                [v for v in all_vulnerabilities if v.severity.upper() == "LOW"]
            ),
            "tools_run": scan_types,
            "scan_duration": "N/A",
        }

        # Update scan results
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "status": "completed",
            "created_at": scan_results[scan_id]["created_at"],
            "completed_at": datetime.now(),
            "results": results,
            "summary": summary,
            "vulnerabilities": [v.dict() for v in all_vulnerabilities],
            "errors": [],
        }
        scan_status[scan_id] = "completed"

    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["errors"].append(str(e))
        scan_status[scan_id] = "failed"

    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(scan_dir)
        except Exception:
            pass


# API Routes
@app.get("/", response_class=HTMLResponse)
async def home():
    """Home page"""
    try:
        async with aiofiles.open("index.html", "r", encoding="utf-8") as f:
            content = await f.read()
        return HTMLResponse(content=content)
    except FileNotFoundError:
        return HTMLResponse(
            content="""
        <html>
        <head><title>CodeSec Scanner</title></head>
        <body>
        <h1>CodeSec Scanner</h1>
        <p>index.html file not found. Please ensure index.html is in the same directory as main.py</p>
        </body>
        </html>
        """,
            status_code=404,
        )


@app.post("/scan/upload")
async def scan_uploaded_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    scan_types: List[str] = Form(...),
):
    """Scan uploaded files"""
    scan_id = str(uuid.uuid4())

    # Create temporary directory for uploaded files
    temp_dir = tempfile.mkdtemp(prefix=f"codesec_scan_{scan_id}_")

    try:
        # Save uploaded files
        for file in files:
            if file.filename is None:
                continue

            file_path = os.path.join(temp_dir, file.filename)
            async with aiofiles.open(file_path, "wb") as f:
                content = await file.read()
                await f.write(content)

            # Extract if it's an archive
            if file.filename.endswith((".zip", ".tar.gz", ".tar", ".tgz")):
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                await extract_archive(file_path, extract_dir)
                # Use extracted directory for scanning
                temp_dir = extract_dir

        # Initialize scan result
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "created_at": datetime.now(),
            "completed_at": None,
            "results": None,
            "errors": [],
        }

        # Start background scan
        background_tasks.add_task(perform_security_scan, scan_id, temp_dir, scan_types)

        return {"scan_id": scan_id, "status": "started"}

    except Exception as e:
        # Clean up on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/debug/test-bandit")
async def test_bandit_endpoint():
    """Test endpoint to diagnose bandit issues"""
    try:
        # Test basic bandit availability
        bandit_available = await test_scanner_availability("bandit")

        # Test on the vulnerable test file we created
        test_file_path = Path("test_bandit.py")
        if test_file_path.exists():
            file_scan_result = await run_bandit_scan(str(test_file_path))
        else:
            file_scan_result = {"error": "test_bandit.py not found"}

        # Get bandit executable info
        bandit_exe = get_scanner_executable("bandit")

        # Test simple bandit version command
        version_cmd = [bandit_exe, "-m", "bandit", "--version"]
        version_result = await run_command(version_cmd, timeout=30)

        return {
            "bandit_available": bandit_available,
            "bandit_executable": bandit_exe,
            "version_test": version_result,
            "test_file_scan": file_scan_result,
            "test_file_exists": test_file_path.exists(),
        }
    except Exception as e:
        return {"error": str(e), "type": type(e).__name__}


@app.post("/scan/github")
async def scan_github_repository(
    background_tasks: BackgroundTasks, request: ScanRequest
):
    """Scan GitHub repository"""
    if not request.github_url:
        raise HTTPException(status_code=400, detail="GitHub URL is required")

    scan_id = str(uuid.uuid4())

    # Create temporary directory for cloned repository
    temp_dir = tempfile.mkdtemp(prefix=f"codesec_github_{scan_id}_")

    try:
        # Clone repository
        if not await clone_repository(str(request.github_url), temp_dir):
            raise HTTPException(status_code=400, detail="Failed to clone repository")

        # Initialize scan result
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "created_at": datetime.now(),
            "completed_at": None,
            "results": None,
            "errors": [],
        }

        # Start background scan
        background_tasks.add_task(
            perform_security_scan, scan_id, temp_dir, request.scan_types
        )

        return {"scan_id": scan_id, "status": "started"}

    except Exception as e:
        # Clean up on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/code")
async def scan_code_content(
    background_tasks: BackgroundTasks, request: CodeScanRequest
):
    """Scan code content"""
    if not request.code_content or not request.code_content.strip():
        raise HTTPException(status_code=400, detail="Code content is required")

    scan_id = str(uuid.uuid4())

    # Create temporary directory for code file
    temp_dir = tempfile.mkdtemp(prefix=f"codesec_code_{scan_id}_")

    try:
        # Map language to file extension
        language_extensions = {
            "python": ".py",
            "javascript": ".js",
            "java": ".java",
            "cpp": ".cpp",
            "c": ".c",
            "php": ".php",
            "ruby": ".rb",
            "go": ".go",
            "typescript": ".ts",
            "csharp": ".cs",
        }

        extension = language_extensions.get(request.language, ".txt")
        filename = f"code_to_scan{extension}"
        file_path = os.path.join(temp_dir, filename)

        # Write code content to file
        async with aiofiles.open(file_path, "w", encoding="utf-8") as f:
            await f.write(request.code_content)

        # Initialize scan result
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "created_at": datetime.now(),
            "completed_at": None,
            "results": None,
            "errors": [],
        }

        # Start background scan
        background_tasks.add_task(
            perform_security_scan, scan_id, temp_dir, request.scan_types
        )

        return {"scan_id": scan_id, "status": "started"}

    except Exception as e:
        # Clean up on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "status": scan_status.get(scan_id, scan_results[scan_id]["status"]),
        "created_at": scan_results[scan_id]["created_at"],
        "errors": scan_results[scan_id]["errors"],
    }


@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get scan results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]
    if result["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    return result


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
