# RedForge

A production-ready Python framework.

## Installation

```bash
pip install redforge
```

## Development

```bash
# Install in development mode
pip install -e .

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
pyright
```

## Vulnerability Intelligence

TASK-0013 correlates asset-associated technology observations with NVD CPE and
CVE API 2.0 data using conservative exact matching. See
[Vulnerability Intelligence](docs/vulnerability-intelligence.md) for API-key
configuration, NVD attribution and limits, matching behavior, and current
limitations.

## License

MIT License - see [LICENSE](LICENSE) for details.
