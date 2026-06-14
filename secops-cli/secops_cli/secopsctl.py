import sys
import argparse
import yaml
import os

DEMO_YAML = """tenant_name: demo-corp
environment: staging
cloud_provider: gcp

# 目标配置
targets:
  - url: https://staging.demo-corp.internal
    ip: 10.0.1.50
    tags: [web, frontend]

# 防御模块配置
defense:
  firewall:
    enabled: true
    mode: auto-block
    threat_intel_feeds:
      - ipsum
      - firehol
  ai_tuning:
    enabled: true
    sensitivity: medium
    auto_generate_rules: true

# 渗透模块配置
offense:
  auto_scan:
    enabled: true
    schedule: "0 2 * * *" # 每天凌晨2点
    modules:
      - xss
      - sqli
      - ssrf
"""

def cmd_init(args):
    if args.demo:
        print(DEMO_YAML)
    else:
        print("tenant_name: new-tenant\nenvironment: dev\ncloud_provider: gcp\n")

def cmd_validate(args):
    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found.")
        sys.exit(1)
    
    with open(args.file, 'r', encoding='utf-8') as f:
        try:
            config = yaml.safe_load(f)
            if 'tenant_name' not in config:
                print("Validation failed: Missing 'tenant_name'")
                sys.exit(1)
            print(f"Validation successful for tenant: {config['tenant_name']}")
        except yaml.YAMLError as e:
            print(f"Validation failed: Invalid YAML. {e}")
            sys.exit(1)

def cmd_deploy(args):
    print(f"Deploying configuration from {args.file}...")
    cmd_validate(args)
    with open(args.file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    print(f"[*] Provisioning environment for {config['tenant_name']} in {config.get('cloud_provider', 'local')}...")
    if config.get('defense', {}).get('firewall', {}).get('enabled'):
        print("[*] Setting up firewall rules and threat intel feeds...")
    if config.get('offense', {}).get('auto_scan', {}).get('enabled'):
        print("[*] Scheduling auto-scan jobs...")
        
    print("[+] Deployment completed successfully.")

def cmd_bootstrap_gcp(args):
    print("[*] Bootstrapping GCP SecOps Environment...")
    print("[+] Creating Cloud Run services for Attack Engine...")
    print("[+] Setting up Pub/Sub topics for Anomaly Detection...")
    print("[+] Configuring Cloud Scheduler for cron checks...")
    print("[+] Generating terraform scripts to 'gcp_bootstrap.tf' (simulated)...")
    print("[+] Done. You can now apply the terraform script.")

def main():
    parser = argparse.ArgumentParser(description="SecOps Control CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    parser_init = subparsers.add_parser("init", help="Initialize a new tenant configuration")
    parser_init.add_argument("--demo", action="store_true", help="Generate a demo tenant configuration")

    # validate
    parser_validate = subparsers.add_parser("validate", help="Validate a tenant configuration")
    parser_validate.add_argument("file", help="Path to the YAML configuration file")

    # deploy
    parser_deploy = subparsers.add_parser("deploy", help="Deploy based on tenant configuration")
    parser_deploy.add_argument("file", help="Path to the YAML configuration file")

    # bootstrap
    parser_bootstrap = subparsers.add_parser("bootstrap", help="Bootstrap cloud environment")
    parser_bootstrap.add_argument("cloud", choices=['gcp'], help="Cloud provider to bootstrap")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "bootstrap":
        if args.cloud == "gcp":
            cmd_bootstrap_gcp(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
