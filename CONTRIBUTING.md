# Contributing to DomainSieve

Thanks for your interest in the project.

## Code style

Python code follows PEP 8.

- **Naming:** snake_case for functions and variables (for example
  `fetch_phishing_urls`).
- **Structure:** core logic lives in modular functions, with the
  execution flow inside `main()`.
- **Formatting:** 4 spaces per indentation level, two blank lines between
  top-level functions.
- **Linting:** run `black` or `flake8` before opening a pull request.

## Types of contributions

### Attack signatures (HTTP/TLS rules)

For new or changed URL signatures:

- Follow the Suricata ruleset structure used in this project.
- Keep the variables, metadata formats (`created_et`), and
  classification types (`social-engineering`) consistent.
- Open a pull request with the rule additions.

### DNS rules

For new malicious domains in the DNS threat feed:

- Do not modify the Python logic for this. Append the domains directly
  to `phishing.lst`.
- Open a pull request with the updated list.

### Documentation

Improvements to the README, tutorials, or usage notes:

- Open an issue describing the change first.
- After discussion, open a pull request for the markdown files.

### Bugs and feedback

Open an issue for bugs, feature requests, or rule updates you cannot
provide as code.

## How to submit a pull request

1. Fork the repository.
2. Clone your fork.
3. Create a branch for your change.
4. Commit with a clear message, for example
   `git commit -m "Add malicious domain to phishing.lst"`.
5. Push to your branch.
6. Open a pull request against `main`.
