# BloodHound MCP Server

A Model Context Protocol server for [BloodHound](https://github.com/BloodHoundAD/BloodHound), the industry-standard tool for visualizing and analyzing Active Directory attack paths.

> **Note**: This MCP server wraps [MorDavid/BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI).

## Tools

Provides 75+ specialized query functions based on BloodHound's Cypher queries, including:

| Tool | Description |
|------|-------------|
| `find_all_domain_admins` | List all Domain Admin accounts |
| `find_kerberoastable_users` | Find users vulnerable to Kerberoasting |
| `find_asreproastable_users` | Find users vulnerable to AS-REP Roasting |
| `find_paths_to_da` | Find attack paths to Domain Admins |
| `find_unconstrained_delegation` | Find systems with unconstrained delegation |
| `find_gpo_permissions` | Analyze GPO permissions |

## Features

- **Natural Language Queries**: Ask questions like "Show me all paths from kerberoastable users to Domain Admins"
- **Attack Path Analysis**: Visualize and understand AD attack chains
- **Privilege Escalation**: Identify privilege escalation opportunities
- **Security Assessment**: Generate security reports

## Requirements

- BloodHound 4.x+ with collected Active Directory data
- Neo4j database containing BloodHound data
- Neo4j connection credentials

## Docker

### Build

```bash
docker build -t bloodhound-mcp .
```

### Run

```bash
docker run --rm -i \
  -e NEO4J_URI=bolt://neo4j:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASSWORD=your_password \
  bloodhound-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bloodhound": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "NEO4J_URI=bolt://localhost:7687",
        "-e", "NEO4J_USER=neo4j",
        "-e", "NEO4J_PASSWORD",
        "bloodhound-mcp"
      ],
      "env": {
        "NEO4J_PASSWORD": "your_password_here"
      }
    }
  }
}
```

## Security Notice

This tool is designed for authorized Active Directory security assessments only. Always ensure you have proper authorization before analyzing any Active Directory environment.

## License

MIT
