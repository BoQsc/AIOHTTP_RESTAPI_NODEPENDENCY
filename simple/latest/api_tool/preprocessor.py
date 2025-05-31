import sys
import re
import requests

def transform_and_execute(source_code, base_url='http://localhost:8000'):
    """Transform DSL syntax to Python and execute"""
    
    # HTTP processor embedded in the generated code
    processor_code = f'''import requests

class HTTPRequestProcessor:
    def __init__(self, base_url='{base_url}'):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def execute_request(self, method, endpoint, json_data=None, headers=None, max_retries=0):
        url = f"{{self.base_url}}{{endpoint}}"
        kwargs = {{}}
        if json_data:
            kwargs['json'] = json_data
        if headers:
            kwargs['headers'] = headers
        
        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                response = self.session.request(method.upper(), url, **kwargs)
                print(f"{{method.upper()}} {{url}} -> {{response.status_code}}")
                if json_data:
                    print(f"  Sent: {{json_data}}")
                if response.text:
                    try:
                        response_json = response.json()
                        print(f"  Response: {{response_json}}")
                    except:
                        print(f"  Response: {{response.text[:100]}}...")
                return response
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    print(f"  Retry {{attempt + 1}}/{{max_retries}} after error: {{e}}")
                else:
                    print(f"  Failed after {{max_retries}} retries: {{e}}")
        if last_exception:
            raise last_exception
        return response

_processor = HTTPRequestProcessor()
'''
    
    lines = source_code.split('\n')
    output = [processor_code.strip()]
    output.append('')
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            output.append(line)
            i += 1
            continue
            
        # Skip preprocessor import and BASE_URL
        if 'import preprocessor' in stripped or 'BASE_URL' in stripped:
            i += 1
            continue
        
        # Match HTTP methods
        http_match = re.match(r'^(\s*)(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s:]*):?\s*$', line)
        
        if http_match:
            indent = http_match.group(1)
            method = http_match.group(2)
            endpoint = http_match.group(3)
            
            json_data = None
            headers = None
            max_retries = 0
            
            # Parse parameters from following lines
            i += 1
            while i < len(lines):
                param_line = lines[i]
                param_stripped = param_line.strip()
                
                if not param_stripped or param_stripped.startswith('#'):
                    i += 1
                    continue
                
                # Stop at next HTTP method or unindented code
                if (re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s+/', param_stripped) or
                    (param_stripped and not param_line.startswith(('    ', '\t')) and 
                     not param_stripped.startswith(('json', 'headers', 'max_retries')))):
                    break
                
                # Parse json (handle multiline)
                if param_stripped.startswith('json'):
                    json_text = param_stripped
                    brace_count = json_text.count('{') - json_text.count('}')
                    
                    while brace_count > 0 and i + 1 < len(lines):
                        i += 1
                        json_text += ' ' + lines[i].strip()
                        brace_count = json_text.count('{') - json_text.count('}')
                    
                    json_match = re.search(r'json\s*=\s*(\{.*\})', json_text, re.DOTALL)
                    if json_match:
                        json_data = json_match.group(1)
                
                elif param_stripped.startswith('headers'):
                    headers_match = re.search(r'headers\s*=\s*(\{.*\})', param_stripped)
                    if headers_match:
                        headers = headers_match.group(1)
                
                elif param_stripped.startswith('max_retries'):
                    retries_match = re.search(r'max_retries\s*=\s*(\d+)', param_stripped)
                    if retries_match:
                        max_retries = int(retries_match.group(1))
                
                i += 1
            
            # Generate method call
            params = [f"'{method}'", f"'{endpoint}'"]
            if json_data:
                params.append(f"json_data={json_data}")
            if headers:
                params.append(f"headers={headers}")
            if max_retries > 0:
                params.append(f"max_retries={max_retries}")
            
            output.append(f"{indent}_processor.execute_request({', '.join(params)})")
            output.append('')
            continue
        
        output.append(line)
        i += 1
    
    # Execute the transformed code
    transformed = '\n'.join(output)
    exec(transformed, {'__name__': '__main__'})

def run_dsl_file(filepath):
    """Load and execute a DSL file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()
    
    # Extract BASE_URL
    base_url = 'http://localhost:8000'
    base_url_match = re.search(r"BASE_URL\s*=\s*['\"]([^'\"]+)['\"]", source)
    if base_url_match:
        base_url = base_url_match.group(1)
    
    transform_and_execute(source, base_url)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_dsl_file(sys.argv[1])
    else:
        print("Usage: python preprocessor.py test_script.py")