# Contributing to Arkade Go SDK

Thank you for your interest in contributing to the Arkade Go SDK! We welcome contributions of all kinds—whether it’s reporting bugs, suggesting enhancements, improving documentation, or submitting pull requests.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:

   ```bash
   git clone https://github.com/your-username/go-sdk.git
   cd go-sdk
   ```
3. **Install dependencies** and set up your environment:

   ```bash
   go mod download
   ```

4. **Lint code** after you're done with the changes:

   ```bash
   make lint
   ```

5. **Run tests** to ensure everything is working:

   ```bash
   make test
   ```

## How to Report Bugs

1. Create a new issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
2. Provide a clear and descriptive title.
3. Include steps to reproduce, expected behavior, and any relevant logs or screenshots.

## How to Suggest Enhancements

1. Create a new issue using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).
2. Clearly describe the use case, proposed solution, and any alternatives you’ve considered.

## Pull Request Process

1. **Sync** your fork with upstream:

   ```bash
   git fetch upstream
   git rebase upstream/master
   ```
2. **Create a new branch** for your change:

   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes** in the new branch.
4. **Follow our code style** (see below).
5. **Add tests** for any new functionality.
6. **Run all tests** and linters:

   ```bash
   make lint
   make test
   ```
7. **Commit changes** with a clear message (see commit guidelines below).
8. **Push** your branch to your fork:

   ```bash
   git push origin feature/my-feature
   ```
9. **Open a pull request** against `master` in this repository.

## Coding Style

* Follow [Go formatting](https://golang.org/cmd/go/#hdr-Formatting_using_gofmt) (`gofmt`).
* Use `make lint` (makes use of `golangci-lint` and fallbacks to dockerized version if not installed).
* Keep functions small and focused; aim for clear, readable code.

## Running Tests

* Run unit tests:

  ```bash
  make test
  ```

## Commit Message Guidelines

* Use the imperative mood in the subject line (e.g., “Add feature” not “Added feature”).
* Limit the subject line to 50 characters.
* Wrap the body at 72 characters.
* Reference issues and pull requests liberally.

## Code Reviews

* All PRs must be reviewed by at least one core maintainer.
* Reviewers will comment on improvements or ask for clarifications.
* Aim to address review comments promptly.

---

Thanks again for helping improve **Arkade Go SDK**! We appreciate your time and effort.
