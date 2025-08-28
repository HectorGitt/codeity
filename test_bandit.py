import os
import tempfile
import asyncio
from main import run_bandit_scan

# Create a simple test file with a vulnerability
test_code = '''
import os

def vulnerable_command(user_input):
    os.system(f"ls {user_input}")  # Command injection vulnerability
'''

async def test_bandit():
    # Create a temporary directory with a test file
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write(test_code)
        
        # Run bandit scan
        result = await run_bandit_scan(temp_dir)
        print("Bandit scan result:")
        print(f"Status: {result['status']}")
        print(f"Tool: {result['tool']}")
        
        if result['status'] == 'success':
            print(f"Found {len(result['vulnerabilities'])} vulnerabilities")
            for vuln in result['vulnerabilities']:
                print(f"- {vuln.severity}: {vuln.description}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    asyncio.run(test_bandit())
