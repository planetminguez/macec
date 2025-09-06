# Contributing to macsec

Thanks for your interest in improving macsec! Contributions of all kinds are welcome: bug reports, feature requests, documentation, and code.

## Getting started

1. Fork the repository and create a feature branch:
   - git checkout -b feature/your-feature
2. Build locally:
   - make
3. Run a quick smoke test:
   - ./macsec /bin/ls

## Coding guidelines

- C99, warnings enabled: -Wall -Wextra
- Keep changes focused and small where possible
- Prefer clear, portable code over clever code
- Follow existing patterns in macsec.c (e.g., error handling, output formatting)

## Commit messages

- Use concise, descriptive messages
- Reference issues when applicable (e.g., Fixes #123)

## Pull requests

- Ensure the project builds (Makefile) and passes the GitHub Actions CI
- Include tests or sample outputs if you add notable functionality
- Update README.md when you change usage or visible behavior

## Reporting issues

- Include macOS version and Xcode CLT version if relevant
- Include steps to reproduce and example binaries/paths if possible

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see LICENSE).

