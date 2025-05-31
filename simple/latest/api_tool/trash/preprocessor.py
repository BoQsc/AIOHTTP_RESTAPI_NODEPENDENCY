import sys
import re
import ast
import requests
import json as json_module
from typing import Dict, Any, Optional
import tempfile
import os

class HTTPRequestProcessor:
    def __init__(self, base_url: str = 'http://localhost:8000'):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def execute_request(self, method: str, endpoint: str, 
                       json_data: Optional[Dict] = None, 
                       headers: Optional[Dict] = None, 
                       max_retries: int = 0) -> requests.Response:
        """Execute HTTP request with retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        kwargs = {}
        if json_data:
            kwargs['json'] = json_data
        if headers:
            kwargs['headers'] = headers
        
        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                response = self.session.request(method.upper(), url, **kwargs)
                print(f"{method.upper()} {url} -> {response.status_code}")
                if json_data:
                    print(f"  Sent: {json_data}")
                if response.text:
                    try:
                        response_json = response.json()
                        print(f"  Response: {response_json}")
                    except:
                        print(f"  Response: {response.text[:100]}...")
                return response
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    print(f"  Retry {attempt + 1}/{max_retries} after error: {e}")
                else:
                    print(f"  Failed after {max_retries} retries: {e}")
        
        if last_exception:
            raise last_exception
        return response


def transform_dsl_to_python(content: str) -> str:
    """Transform DSL syntax to valid Python code"""
    lines = content.split('\n')
    output_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        original_line = line
        stripped = line.strip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            output_lines.append(line)
            i += 1
            continue
        
        # Handle import and BASE_URL
        if stripped.startswith('import ') or 'BASE_URL' in stripped:
            output_lines.append(line)
            i += 1
            continue
        
        # Check for HTTP method patterns
        http_match = re.match(r'^(\s*)(GET|POST|PUT|DELETE|PATCH)\s+([^\s:]+):?\s*$', line)
        
        if http_match:
            indent = http_match.group(1)
            method = http_match.group(2)
            endpoint = http_match.group(3)
            
            # Start building the function call
            output_lines.append(f"{indent}# {method} {endpoint}")
            output_lines.append(f"{indent}_processor.execute_request('{method}', '{endpoint}',")
            
            # Look for parameters in following lines
            params = []
            json_data = None
            headers = None
            max_retries = 0
            
            i += 1
            while i < len(lines):
                param_line = lines[i]
                param_stripped = param_line.strip()
                
                if not param_stripped or param_stripped.startswith('#'):
                    i += 1
                    continue
                
                # Check if this is another HTTP method or regular Python code
                if re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s+', param_stripped) or \
                   (param_stripped and not param_stripped.startswith(('json', 'headers', 'max_retries'))):
                    break
                
                # Parse json parameter
                if param_stripped.startswith('json'):
                    json_text = param_stripped
                    # Handle multi-line json
                    brace_count = json_text.count('{') - json_text.count('}')
                    while brace_count > 0 and i + 1 < len(lines):
                        i += 1
                        next_line = lines[i].strip()
                        json_text += ' ' + next_line
                        brace_count += next_line.count('{') - next_line.count('}')
                    
                    # Extract the dictionary
                    json_match = re.search(r'json\s*=\s*(\{.*\})', json_text)
                    if json_match:
                        json_data = json_match.group(1)
                
                # Parse headers parameter
                elif param_stripped.startswith('headers'):
                    headers_match = re.search(r'headers\s*=\s*(\{.*\})', param_stripped)
                    if headers_match:
                        headers = headers_match.group(1)
                
                # Parse max_retries parameter
                elif param_stripped.startswith('max_retries'):
                    retries_match = re.search(r'max_retries\s*=\s*(\d+)', param_stripped)
                    if retries_match:
                        max_retries = int(retries_match.group(1))
                
                i += 1
            
            # Complete the function call
            if json_data:
                output_lines.append(f"{indent}    json_data={json_data},")
            else:
                output_lines.append(f"{indent}    json_data=None,")
            
            if headers:
                output_lines.append(f"{indent}    headers={headers},")
            else:
                output_lines.append(f"{indent}    headers=None,")
            
            output_lines.append(f"{indent}    max_retries={max_retries})")
            output_lines.append("")
            
            continue
        
        # Handle regular Python code
        else:
            output_lines.append(line)
            i += 1
    
    return '\n'.join(output_lines)


def preprocess_and_run():
    """Main preprocessor function called when module is imported"""
    # Get the calling frame to read the script
    frame = sys._getframe(1)
    filename = frame.f_code.co_filename
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # Extract BASE_URL if defined
    base_url = 'http://localhost:8000'
    base_url_match = re.search(r"BASE_URL\s*=\s*['\"]([^'\"]+)['\"]", content)
    if base_url_match:
        base_url = base_url_match.group(1)
    
    # Transform DSL to Python
    transformed_content = transform_dsl_to_python(content)
    
    # Add processor initialization at the beginning
    processor_init = f"""
import requests
import json as json_module
from preprocessor import HTTPRequestProcessor

_processor = HTTPRequestProcessor('{base_url}')
"""
    
    # Find where to insert the processor (after imports but before DSL)
    lines = transformed_content.split('\n')
    insert_index = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('import ') or line.strip().startswith('from ') or 'BASE_URL' in line:
            insert_index = i + 1
        elif line.strip() and not line.strip().startswith('#'):
            break
    
    lines.insert(insert_index, processor_init)
    final_content = '\n'.join(lines)
    
    # Create a temporary file and execute it
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(final_content)
        temp_filename = f.name
    
    try:
        # Execute the transformed file
        with open(temp_filename, 'r') as f:
            exec(f.read(), {'__name__': '__main__'})
    finally:
        # Clean up
        os.unlink(temp_filename)


# Auto-execute when imported
if __name__ != '__main__':
    preprocess_and_run()
    sys.exit(0)