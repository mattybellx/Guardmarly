# Good First Issues

> New to Ansede? Start here! These issues are designed for first-time contributors.

## How to Pick Your First Issue

1. **Browse the list below** and pick something that interests you
2. **Comment on the issue** saying you'd like to work on it
3. **Read [CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions
4. **Ask questions!** We're happy to help in [GitHub Discussions](https://github.com/mattybellx/Ansede/discussions)

## Issue Types (Easiest → Hardest)

### 🟢 Level 1: Documentation & Examples
No coding required. Great for first-time open-source contributors.

- Fix typos or unclear explanations in docs
- Add examples to existing documentation
- Improve error messages
- Write a tutorial for a specific use case

### 🟡 Level 2: Community Rules
Basic YAML knowledge needed. See [Writing Rules](docs/writing-rules.md).

- Write a detection rule for a missing CWE
- Improve an existing rule's pattern
- Add framework-specific patterns (Laravel, Rails, Gin, etc.)
- Create rule tests

### 🟠 Level 3: Bug Fixes
Python knowledge needed. Good for developers comfortable with the language.

- Fix a reported false positive
- Improve parse error handling
- Add a small CLI improvement
- Fix a test that's flaky

### 🔴 Level 4: Features
Requires understanding of the analysis engine. Read the architecture docs first.

- Add support for a new framework pattern
- Improve detection in an existing language
- Add a new output format
- Performance optimization

## Current Good First Issues

<!-- These are examples. Actual issues should be tagged with 'good first issue' on GitHub. -->

1. **Add documentation for `--baseline` flag** (Level 🟢)
   - The `--baseline` flag is powerful but undocumented in the getting-started guide
   - Write a clear explanation with examples

2. **Create a community rule for Express.js rate limiting** (Level 🟡)
   - Detect missing `express-rate-limit` middleware
   - Follow the template in `community_rules/`

3. **Improve the "no findings" message** (Level 🟠)
   - When a scan finds nothing, show a more helpful message
   - Suggest `ansede-static --demo` to see what findings look like

4. **Add a "did you know?" tip system** (Level 🟠)
   - Show random security tips after scans
   - Educational and engaging

5. **Translate error messages to be more user-friendly** (Level 🟢)
   - Parse errors are currently technical
   - Make them understandable for non-security-engineers

## Getting Help

- 💬 [GitHub Discussions](https://github.com/mattybellx/Ansede/discussions) — best for questions
- 🐛 [Issue Tracker](https://github.com/mattybellx/Ansede/issues) — for bugs
- 📖 [Documentation](docs/index.md) — comprehensive guides

---

*Never contributed to open source before? That's fine! We remember what it was like to start and we're happy to help.*
