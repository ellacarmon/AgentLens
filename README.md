# ai-guard
![License](https://img.shields.io/badge/License-GPL_v3-blue.svg)

`ai-guard` is a deterministic, pre-installation security wrapper for AI Agent skills, tools, and repositories.

It forces targeted code to run through a custom static analysis risk scoring model before allowing it to interact with your execution environment, aggressively identifying common vulnerabilities introduced by AI-generated external dependencies.

## Key Features
- **Deterministic Scanning:** Fully bounded risk scoring engine that prevents unbounded linear score accumulation.
- **Categorical Risk Silos:** Independent evaluation of `code_execution`, `prompt_injection`, `filesystem_access`, and `network_access`.
- **Probabilistic Scoring:** Granular probabilistic overall evaluation curve that reliably isolates true critical severity code blocks.
- **Output Formats:** Rich CLI formatting for human reviewers, or full `Pydantic`-validated JSON for programmatic aggregation.

## Installation

You can install `ai-guard` locally using pip:

```bash
git clone https://github.com/TODO/ai-guard.git
cd ai-guard
pip install .
```

## Usage

You can scan direct remote repositories without installing them locally:

```bash
ai-guard scan https://github.com/alirezarezvani/claude-skills
```

To integrate into programmatic pipelines (such as a GitHub action or a pre-flight execution check), use `--json`:

```bash
ai-guard scan https://github.com/alirezarezvani/claude-skills --json
```

To enforce a strict threshold, causing the CLI to exit with a non-zero system code:

```bash
ai-guard scan ./local_skill_folder --fail-on-risk 7.0
```

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting pull requests to the project.

## License
This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
