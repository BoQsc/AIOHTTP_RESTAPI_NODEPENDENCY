# Check what's inside your PEM file
def check_pem_content(filename):
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        print(f"File: {filename}")
        print(f"File size: {len(content)} characters")
        print("\n--- Content Analysis ---")
        
        # Check for certificates
        cert_count = content.count('-----BEGIN CERTIFICATE-----')
        print(f"Certificates found: {cert_count}")
        
        # Check for private key
        key_patterns = [
            '-----BEGIN PRIVATE KEY-----',
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN EC PRIVATE KEY-----'
        ]
        
        key_found = False
        for pattern in key_patterns:
            if pattern in content:
                print(f"Private key found: {pattern}")
                key_found = True
                break
        
        if not key_found:
            print("❌ NO PRIVATE KEY FOUND - This is your problem!")
        
        # Show first few lines
        print("\n--- First 10 lines ---")
        lines = content.split('\n')[:10]
        for i, line in enumerate(lines, 1):
            print(f"{i}: {line}")
            
        return key_found, cert_count
        
    except Exception as e:
        print(f"Error reading file: {e}")
        return False, 0

# Run the check
key_found, cert_count = check_pem_content('boqsc.eu_fullchain.pem')