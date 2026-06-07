# Third-Party Notices

This graduation project includes several substantially modified MCP server
components. Some portions are derived from MIT-licensed open-source MCP server
code and are retained with the required license notices.

## MCP Servers

The following directories contain modified MCP server implementations used as
infrastructure for the AI-powered SOC/NIDS workflow:

- `zeek-mcp`
- `suricata-mcp`
- `wazuh-mcp`
- `mitre-mcp`

These components are distributed under the MIT License in their respective
`LICENSE` files. Keep those license files and copyright notices with the code
unless you have a separate written permission file that explicitly changes the
license/notice requirements.

## Project Contribution

The graduation-project work in this workspace includes the integration and
configuration around these components, including:

- the AI SOC agent configuration for Gemini
- the Wazuh-primary investigation prompt and decision policy
- MCP tool orchestration and read-only safety configuration
- environment templates for the lab topology
- the end-to-end NIDS/SOAR architecture and deployment plan

When presenting or submitting the project, describe the MCP servers as modified
or adapted components and focus the original contribution on the architecture,
implementation changes, integration, configuration, testing, and SOC automation
workflow.
