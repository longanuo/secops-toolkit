# MCP Server for Cybersecurity-Ops

This module provides a Model Context Protocol (MCP) server that exposes cybersecurity operations tools as callable functions for AI agents like Mimocode.

## Overview

The MCP server wraps the existing `secops-cli` functionality and exposes it through a standardized protocol that AI agents can use to:

1. **Solve CTF challenges** across multiple categories (web, pwn, reverse, crypto, forensics, misc)
2. **Scan vulnerabilities** in web applications
3. **Perform server health checks** and security assessments
4. **Run sandbox tests** for vulnerability reproduction
5. **Learn from GitHub repositories** to extract attack patterns
6. **Update firewall rules** with threat intelligence
7. **Apply security hardening** measures

## Installation

The MCP server is included in the `cybersecurity-ops` package. After installation:

```bash
pip install -e .
```

The `secops-mcp` command will be available.

## Usage

### As a stdio MCP Server

The server communicates via stdin/stdout using JSON-RPC 2.0 protocol:

```bash
secops-mcp
```

### Integration with AI Agents

#### For Mimocode

Add the following to your Mimocode configuration:

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

#### For Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": []
    }
  }
}
```

#### For Cursor

Add to your Cursor MCP configuration:

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": []
    }
  }
}
```

## Available Tools

### 1. solve_ctf_challenge

Solve CTF challenges across multiple categories.

**Parameters:**
- `challenge_type` (required): Type of challenge (web, pwn, reverse, crypto, forensics, misc)
- `challenge_url` (optional): URL for web-based challenges
- `file_path` (optional): Path to binary or attachment files
- `description` (optional): Challenge description
- `hints` (optional): Available hints

### 2. scan_vulnerabilities

Scan target URL for vulnerabilities.

**Parameters:**
- `target_url` (required): Target URL to scan
- `modules` (optional): Vulnerability modules to use (default: all)
- `params` (optional): Additional parameters

### 3. server_health_check

Perform comprehensive server health and security checks.

**Parameters:**
- `server_id` (required): Server identifier or hostname
- `check_type` (optional): Type of check (full, quick, incident)
- `log_paths` (optional): Log file paths to analyze

### 4. sandbox_test

Run tests in isolated sandbox environments.

**Parameters:**
- `test_type` (required): Type of test (stability, vuln_repro, ctf_env)
- `target_image` (required): Docker image or environment
- `test_duration_min` (optional): Test duration in minutes
- `resource_limits` (optional): Resource limits for sandbox

### 5. learn_from_github

Learn attack patterns from GitHub repositories.

**Parameters:**
- `repos` (required): GitHub repositories to learn from
- `extract_rules` (optional): Whether to extract security rules
- `apply_to_firewall` (optional): Whether to apply rules to firewall

### 6. update_firewall

Manage firewall rules with threat intelligence.

**Parameters:**
- `action` (required): Firewall action (add_rules, remove_rules, full_update, audit)
- `intel_file` (optional): Path to threat intelligence file
- `manual_rules` (optional): Manual firewall rules to apply

### 7. run_hardening

Apply security hardening measures.

**Parameters:**
- `target_os` (optional): Target operating system (linux, windows)
- `modules` (optional): Hardening modules to apply

## Configuration

The server uses `mcp_config.json` for configuration. See the configuration file for details on:

- Server settings
- Tool-specific timeouts
- Security policies (allowed/blocked targets)
- Logging configuration

## Security Considerations

1. **Authorization**: The server checks target authorization before scanning
2. **Blocked Targets**: Government, military, and educational domains are blocked by default
3. **Allowed Targets**: Only localhost and private networks are allowed by default
4. **Timeouts**: Each tool has configurable timeouts to prevent abuse

## Output Format

All tools return results following the unified output schema defined in `mimocode-integration.md`:

```json
{
  "$schema": "cybersecurity-ops/v1",
  "skill": "cybersecurity-ops",
  "mode": "<tool_mode>",
  "task_id": "<mode>-<date>-<sequence>",
  "status": "completed|failed|in_progress",
  "execution": { ... },
  "artifacts": [ ... ],
  "findings": [ ... ],
  "habit_hints": { ... },
  "next_actions": [ ... ],
  "tags": [ ... ]
}
```

## Development

### Adding New Tools

1. Add tool definition in `_define_tools()`
2. Implement the tool method
3. Add tool execution in `_execute_tool()`
4. Update configuration if needed

### Testing

Test the MCP server with a simple JSON-RPC request:

```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | secops-mcp
```

## Troubleshooting

### Common Issues

1. **Tool not found**: Ensure the tool is enabled in configuration
2. **Authorization failed**: Check target against allowed_targets
3. **Timeout**: Increase timeout in configuration
4. **Import errors**: Ensure all dependencies are installed

### Logs

Check `mcp_server.log` for detailed error information.

## Example Usage

### 1. List available tools

```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | secops-mcp
```

### 2. Scan for vulnerabilities

```bash
echo '{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "scan_vulnerabilities",
    "arguments": {
      "target_url": "http://localhost:8080",
      "modules": ["xss", "sqli"]
    }
  }
}' | secops-mcp
```

### 3. Learn from GitHub

```bash
echo '{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "learn_from_github",
    "arguments": {
      "repos": ["vulhub/vulhub"],
      "extract_rules": true
    }
  }
}' | secops-mcp
```

### 4. Run system hardening

```bash
echo '{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "run_hardening",
    "arguments": {
      "target_os": "linux",
      "modules": ["ssh", "password", "sysctl"]
    }
  }
}' | secops-mcp
```

## Integration Examples

### Mimocode Configuration

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": []
    }
  }
}
```

### Cursor Configuration

```json
{
  "mcpServers": {
    "cybersecurity-ops": {
      "command": "secops-mcp",
      "args": []
    }
  }
}
```

## License

MIT License - same as the main cybersecurity-ops project.