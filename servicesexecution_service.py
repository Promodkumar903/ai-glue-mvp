import os
import subprocess
import tempfile
import time
from config import Config

def run_sandbox(code):
    start_time = time.time()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, 'script.py')
            with open(file_path, 'w') as f:
                f.write(code)
            result = subprocess.run(
                ['python', file_path],
                capture_output=True,
                text=True,
                timeout=Config.SANDBOX_TIMEOUT,
                cwd=tmpdir
            )
            output = result.stdout if result.stdout else result.stderr
            return output, round(time.time() - start_time, 2)
    except subprocess.TimeoutExpired:
        return '⏰ Timeout (5s)', 5.0
    except Exception as e:
        return f'❌ Error: {str(e)}', round(time.time() - start_time, 2)