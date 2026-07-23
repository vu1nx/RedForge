# Contributing to RedForge

Thank you for your interest in contributing to RedForge!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/vu1nx/RedForge.git
   cd RedForge
   ```

2. Install in development mode:
   ```bash
   pip install -e .
   ```

3. Install development dependencies:
   ```bash
   pip install ruff pyright pytest
   ```

## Code Quality

Before submitting a pull request, ensure:

- **Ruff** passes: `ruff check .`
- **Pyright** passes: `pyright`
- **Pytest** passes: `pytest`

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run all quality checks
5. Submit a pull request

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
