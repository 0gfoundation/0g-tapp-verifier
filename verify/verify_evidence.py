#!/usr/bin/env python3
import requests
import json
import base64
import sys
import argparse
import urllib3
import os

# disable SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def verify_evidence(verbose=False):
    """verify TDX evidence"""
    # configuration
    gateway_host = "localhost"
    port = "8081"
    evidence_file = "evidence.json"
    
    # read configuration from environment variables
    policy_id = os.environ.get('POLICY_ID', 'tapp')
    image_id = os.environ.get('IMAGE_ID', '')
    instance_id = os.environ.get('INSTANCE_ID', '')
    instance_name = os.environ.get('INSTANCE_NAME', '')
    owner_account_id = os.environ.get('OWNER_ACCOUNT_ID', '')
    
    url = f"http://{gateway_host}:{port}/api/attestation-service/attestation"
    
    # read evidence file
    print(f"read evidence file: {evidence_file}...")
    try:
        with open(evidence_file, 'r') as f:
            evidence_data = json.load(f)
            evidence_body = evidence_data['evidence']
    except FileNotFoundError:
        print(f"✗ {evidence_file} file not found!")
        sys.exit(1)
    except KeyError:
        print("✗ 'evidence' field not found in JSON!")
        sys.exit(1)
    except Exception as e:
        print(f"✗ failed to load evidence: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print(f"  - Evidence base64 length: {len(evidence_body)}")
    print(f"  - use Policy ID: {policy_id}")
    
    # build request payload
    payload = {
        "verification_requests": [{
            "tee": "tdx",
            "evidence": evidence_body
        }],
        "policy_ids": [policy_id]
    }
    
    # request headers
    headers = {
        "Content-Type": "application/json"
    }
    
    # add AAInstanceInfo header only if instance information is provided
    if image_id or instance_id or instance_name or owner_account_id:
        aa_instance_info = {}
        if image_id:
            aa_instance_info["image_id"] = image_id
        if instance_id:
            aa_instance_info["instance_id"] = instance_id
        if instance_name:
            aa_instance_info["instance_name"] = instance_name
        if owner_account_id:
            aa_instance_info["owner_account_id"] = owner_account_id
        headers["AAInstanceInfo"] = json.dumps(aa_instance_info)
        print(f"  - use AAInstanceInfo: {json.dumps(aa_instance_info)}")
    
    try:
        print("\nsend verification request...")
        response = requests.post(url, json=payload, headers=headers, verify=False)
        print(f"HTTP status code: {response.status_code}")
        
        if response.status_code == 200:
            jwt_token = response.text
            print("✓ TDX quote verification succeeded!")
            print()
            
            # decode JWT
            decode_jwt(jwt_token, verbose=verbose)
            
            # save JWT token
            with open('jwt_token.txt', 'w') as f:
                f.write(jwt_token)
            print("\n✓ JWT token is saved to jwt_token.txt")
            
        else:
            print("✗ TDX quote verification failed")
            try:
                error_response = response.json()
                print("error response:")
                print(json.dumps(error_response, indent=2))
            except:
                print(f"error response: {response.text}")
            sys.exit(1)
    
    except requests.exceptions.RequestException as e:
        print(f"✗ request error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"✗ error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def decode_jwt(jwt_token, verbose=False):
    """decode JWT token and extract key information"""
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            print("✗ invalid JWT format")
            return
        
        # decode Header
        header_b64 = parts[0]
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header_json = base64.urlsafe_b64decode(header_b64).decode()
        header = json.loads(header_json)
        
        if verbose:
            print("========== JWT Header ==========")
            print(json.dumps(header, indent=2))
            print()
        
        # decode Payload
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        
        if verbose:
            print("========== JWT Payload (full) ==========")
            print(json.dumps(payload, indent=2))
            print()
        
        # save payload to file
        with open('jwt_payload.json', 'w') as f:
            json.dump(payload, f, indent=2)
        
        if verbose:
            print("✓ JWT payload is saved to jwt_payload.json")
            print()
        
        # extract key information
        print("========== verification result ==========")
        try:
            cpu0 = payload['submods']['cpu0']
            verification_status = cpu0['ear.status']
            print(f"verification status: {verification_status}")
            
            # trustworthiness vector
            if 'ear.trustworthiness-vector' in cpu0:
                trust_vector = cpu0['ear.trustworthiness-vector']
                print("\ntrustworthiness vector:")
                print(f"  - configuration: {trust_vector.get('configuration', 'N/A')}")
                print(f"  - executables: {trust_vector.get('executables', 'N/A')}")
                print(f"  - file-system: {trust_vector.get('file-system', 'N/A')}")
            
            # Report Data
            if 'ear.veraison.annotated-evidence' in cpu0:
                evidence = cpu0['ear.veraison.annotated-evidence']
                if 'tdx' in evidence and 'quote' in evidence['tdx']:
                    report_data = evidence['tdx']['quote']['body'].get('report_data', 'N/A')
                    print(f"\nReport Data: {report_data}")
                
                # UEFI Event Logs - find start_app
                if 'tdx' in evidence and 'uefi_event_logs' in evidence['tdx']:
                    print("\n========== Start App logs ==========")
                    found_start_app = False
                    for log in evidence['tdx']['uefi_event_logs']:
                        if 'details' in log and 'data' in log['details']:
                            data = log['details']['data']
                            if isinstance(data, dict) and data.get('operation') == 'start_app':
                                print(json.dumps(log['details'], indent=2))
                                found_start_app = True
                    
                    if not found_start_app:
                        print("start_app log not found")
                
                # Cryptpilot logs
                if verbose and 'tdx' in evidence and 'uefi_event_logs' in evidence['tdx']:
                    print("\n========== Cryptpilot logs ==========")
                    found_cryptpilot = False
                    for log in evidence['tdx']['uefi_event_logs']:
                        if 'details' in log and 'data' in log['details']:
                            data = log['details']['data']
                            if isinstance(data, dict) and data.get('domain') == 'cryptpilot.alibabacloud.com':
                                print(f"Operation: {data.get('operation', 'N/A')}")
                                print(f"Content: {data.get('content', 'N/A')}")
                                print()
                                found_cryptpilot = True
                    
                    if not found_cryptpilot:
                        print("cryptpilot log not found")
        
        except KeyError as e:
            print(f"✗ JWT payload missing expected fields: {e}")
        except Exception as e:
            print(f"✗ error extracting information: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
    
    except Exception as e:
        print(f"✗ failed to decode JWT: {e}")
        import traceback
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description='verify TDX evidence and decode JWT token',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # basic usage (only show key information)
  ./verify_evidence.py
  
  # detailed mode (show full JWT header and payload)
  ./verify_evidence.py -v
  ./verify_evidence.py --verbose
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='show full JWT header and payload'
    )
    
    args = parser.parse_args()
    
    verify_evidence(verbose=args.verbose)

if __name__ == "__main__":
    main()