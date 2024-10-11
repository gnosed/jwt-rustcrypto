# Contributing to the Rust JWT Library

Thank you for your interest in contributing to this library! We welcome contributions of all kinds, including bug reports, feature requests, documentation improvements, and code contributions. This document outlines how to get started and the processes to follow when contributing to this project.

## How to Contribute

### 1. Reporting Bugs

If you find a bug, please submit an issue on our [GitHub issue tracker](https://github.com/robjsliwa/jwt-rustcrypto/issues) with the following information:

- A clear and concise description of the bug.
- Steps to reproduce the bug.
- Expected behavior and what actually happens.
- Any relevant error messages or logs.
- If applicable, include code snippets or test cases to demonstrate the bug.

### 2. Suggesting Features or Improvements

We appreciate feature suggestions and ideas for improving the library! To suggest a feature:

- Open a [GitHub issue](https://github.com/robjsliwa/jwt-rustcrypto/issues) and describe your suggestion.
- Provide context on why the feature is important and how it improves the library.
- If possible, include details on how the feature could be implemented.

### 3. Submitting Pull Requests

We welcome code contributions in the form of pull requests (PRs). Here’s how to submit a PR:

#### Step 1: Fork the repository

Fork the repository by clicking the “Fork” button on the project’s GitHub page, then clone your fork locally:

```bash
git clone https://github.com/your-username/rust-jwt.git
cd rust-jwt
```

#### Step 2: Create a new branch

Create a new branch for your contribution. We follow the naming convention feature/your-feature-name or bugfix/your-bugfix-name:

```
git checkout -b feature/your-feature-name
```

#### Step 3: Make your changes

Make the necessary code changes, ensuring they follow our code style and guidelines:

- Format the code using cargo fmt.
- Lint the code using cargo clippy.
- Add tests for any new functionality, and make sure all tests pass by running cargo test.

#### Step 4: Commit and push your changes

Once you’re happy with your changes, commit them with a meaningful commit message:

```
git add .
git commit -m "Add feature X to improve Y"
```

Then push your branch to your fork:

```
git push origin feature/your-feature-name
```

#### Step 5: Open a pull request

Navigate to the original repository on GitHub, and open a pull request (PR) from your fork. In the PR description:

- Provide context on the changes you’ve made.
- Reference any related issues (e.g., “Fixes #123”).
- Describe how your changes were tested.

#### Step 6: Review process

A project maintainer will review your PR and may ask for changes. Please respond to any feedback and update your PR accordingly. Once approved, your changes will be merged into the main branch.

### Development Environment Setup

**Prerequisites**

To contribute to the library, you’ll need to install the following:

- Rust (latest stable version)
- cargo (Rust’s package manager, included with Rust)

**Running Tests**

Before submitting your changes, ensure that all tests pass. You can run the test suite using:

```bash
cargo test
```

**Code Formatting**

Ensure that your code follows the standard Rust style by running the following command before submitting your PR:

```bash
cargo fmt
```

**Linting**

Run cargo clippy to catch common mistakes and improve code quality:

```bash
cargo clippy
```

**Adding New Features**

When adding new features, please ensure they are covered by appropriate unit tests. New functionality without tests will not be accepted.

**Community Guidelines**

We expect all contributors to adhere to the following guidelines:

1. Be respectful: Treat others with respect in all interactions. Disagreements are natural, but stay professional and constructive.
2. Be helpful: Provide thoughtful feedback during code reviews, and offer assistance to others when needed.
3. Stay focused: Keep discussions relevant to the issue or pull request at hand. Off-topic comments should be taken elsewhere.

**License**

By contributing to this project, you agree that your contributions will be licensed under the same license as the project: the MIT License.
