# LLM Independence Proposal

## Problem Statement

Currently, AgentLens requires the `openai` package as a core dependency, even though LLM features (semantic analysis and logic audit) are optional CLI flags. This creates:

- **External dependency**: Azure OpenAI API required for `--semantic` and `--logic-audit`
- **Cost**: API calls accumulate quickly in CI/CD pipelines
- **Latency**: 1-3 seconds per LLM call
- **Network requirement**: Cannot run fully offline
- **Availability risk**: Scanner fails if Azure API is down (even with graceful degradation)

## Proposed Solution: Multi-Tier LLM Strategy

### Tier 1: Static-Only (Default)
**Status**: Already implemented ✅

- No LLM required
- Pure AST + YAML rules
- Fast, deterministic, offline
- ~100-500ms per scan

### Tier 2: Local Lightweight Classifiers (NEW)
**Proposal**: Add local ML models as fallback

Two approaches:

#### Option A: Sentence Transformers (Recommended)
```python
# Install: pip install agentlens-scanner[local-semantic]
# Uses: sentence-transformers (~100MB models)

from sentence_transformers import SentenceTransformer, util

class LocalSemanticAnalyzer:
    def __init__(self):
        # Load lightweight embedding model
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # 80MB

        # Malicious code patterns (embeddings pre-computed)
        self.malicious_patterns = [
            "reverse shell connection to external server",
            "exfiltrate environment variables to webhook",
            "decode base64 payload and execute arbitrary code",
            "credential harvesting via os.environ access",
        ]

    def analyze_snippets(self, findings):
        # Convert code to embeddings
        code_texts = [f.evidence for f in findings]
        code_embeddings = self.model.encode(code_texts)
        pattern_embeddings = self.model.encode(self.malicious_patterns)

        # Cosine similarity
        similarities = util.cos_sim(code_embeddings, pattern_embeddings)
        max_similarity = similarities.max().item()

        if max_similarity > 0.75:
            return SemanticVerdict(
                decision=SemanticDecision.BLOCK,
                confidence_score=max_similarity,
                explanation="High similarity to known malicious patterns",
                flagged_pattern="pattern-based detection"
            )
        return None  # Fallback to static verdict
```

**Pros**:
- ✅ 80MB model (fits in memory)
- ✅ CPU-friendly (no GPU needed)
- ✅ ~50ms inference time
- ✅ Completely offline
- ✅ No API costs

**Cons**:
- ⚠️ Less nuanced than GPT-4
- ⚠️ Needs curated pattern library
- ⚠️ May miss novel attacks

#### Option B: Ollama Integration
```python
# Install: pip install agentlens-scanner[ollama]
# Requires: Ollama running locally (ollama serve)

import requests

class OllamaSemanticAnalyzer:
    def __init__(self, model="llama3.2:3b"):  # 2GB model
        self.model = model
        self.base_url = "http://localhost:11434"

    def analyze_snippets(self, findings):
        prompt = self._build_prompt(findings)

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",  # Structured output
            },
            timeout=10
        )

        # Parse JSON response into SemanticVerdict
        # ...
```

**Pros**:
- ✅ Full LLM reasoning (similar to Azure)
- ✅ Completely offline
- ✅ No API costs
- ✅ Privacy (data never leaves machine)

**Cons**:
- ⚠️ Requires Ollama installation
- ⚠️ ~2-5GB model download
- ⚠️ Slower inference (2-10s depending on hardware)
- ⚠️ Quality varies by model

### Tier 3: Azure OpenAI (Current)
**Status**: Keep as premium option

- Best quality analysis
- Fastest cloud inference
- Requires API key + network
- Costs ~$0.001 per scan

## Recommended Implementation Plan

### Phase 1: Make `openai` Optional (Immediate)

```toml
# pyproject.toml
dependencies = [
    "click>=8.1.7",
    "pydantic>=2.7.0",
    "pyyaml>=6.0.1",
    "requests>=2.31.0",
    "rich>=13.7.0",
]

[project.optional-dependencies]
azure = [
    "openai>=1.0.0",
]
local-semantic = [
    "sentence-transformers>=2.0.0",
]
ollama = [
    "ollama-python>=0.1.0",
]
```

### Phase 2: Abstraction Layer

```python
# agentlens/analyzers/base_semantic.py
from abc import ABC, abstractmethod

class BaseSemanticAnalyzer(ABC):
    @abstractmethod
    def analyze_snippets(self, findings: List[Finding]) -> Optional[SemanticVerdict]:
        pass

# agentlens/analyzers/semantic_factory.py
def create_semantic_analyzer(backend: str, **kwargs):
    if backend == "azure":
        from .semantic import AzureSemanticAnalyzer
        return AzureSemanticAnalyzer(**kwargs)
    elif backend == "local":
        from .semantic_local import LocalSemanticAnalyzer
        return LocalSemanticAnalyzer(**kwargs)
    elif backend == "ollama":
        from .semantic_ollama import OllamaSemanticAnalyzer
        return OllamaSemanticAnalyzer(**kwargs)
    else:
        raise ValueError(f"Unknown backend: {backend}")
```

### Phase 3: CLI Updates

```bash
# Default: Static only (no LLM)
agentlens scan ./package

# Local lightweight model (80MB, offline)
agentlens scan ./package --semantic --semantic-backend local

# Ollama (requires ollama serve)
agentlens scan ./package --semantic --semantic-backend ollama --semantic-model llama3.2:3b

# Azure (current behavior)
agentlens scan ./package --semantic --semantic-backend azure --semantic-model gpt-4o-mini
```

### Phase 4: Auto-Detection Fallback Chain

```python
def get_default_semantic_backend():
    # Try backends in order of preference

    # 1. Check Azure credentials
    if os.getenv("AZURE_OPENAI_API_KEY"):
        return "azure"

    # 2. Check if Ollama is running
    try:
        requests.get("http://localhost:11434/api/tags", timeout=1)
        return "ollama"
    except:
        pass

    # 3. Check if local models installed
    try:
        import sentence_transformers
        return "local"
    except ImportError:
        pass

    # 4. No LLM available - use static only
    return None
```

## Benefits of This Approach

1. **No forced dependencies**: `openai` becomes optional
2. **Offline capability**: Local models work without internet
3. **Cost reduction**: Local inference is free
4. **Privacy**: Sensitive code never leaves your machine
5. **CI/CD friendly**: Can run in air-gapped environments
6. **Progressive enhancement**: Start with static, upgrade to LLM when needed
7. **Vendor independence**: Not locked into Azure/OpenAI

## Comparison Table

| Feature | Static | Local (sentence-transformers) | Ollama | Azure |
|---------|--------|-------------------------------|--------|-------|
| Setup | None | `pip install agentlens[local-semantic]` | Install Ollama + model | API key |
| Speed | 200ms | 300ms | 3-10s | 1-3s |
| Quality | Good | Medium | Good-High | Excellent |
| Cost | Free | Free | Free | ~$0.001/scan |
| Offline | ✅ | ✅ | ✅ | ❌ |
| Memory | <100MB | ~200MB | 2-8GB | N/A |
| Dependencies | Minimal | +sentence-transformers | +ollama | +openai |

## Migration Path (Backward Compatible)

```python
# Old code (still works)
agentlens scan ./package --semantic

# Auto-detects backend:
# 1. Azure if AZURE_OPENAI_API_KEY set
# 2. Ollama if running locally
# 3. Local if sentence-transformers installed
# 4. Graceful skip if none available

# Explicit backend selection (new)
agentlens scan ./package --semantic --semantic-backend local
```

## Next Steps

1. ✅ Document the proposal (this file)
2. ⏳ Move `openai` to optional dependencies
3. ⏳ Implement `LocalSemanticAnalyzer` using sentence-transformers
4. ⏳ Add backend selection to CLI
5. ⏳ Update documentation with offline workflows
6. ⏳ (Optional) Add Ollama integration

## Open Questions

1. Should we ship pre-computed embeddings for common malicious patterns?
2. How to handle model updates for local backend?
3. Should we support custom local models (e.g., user-trained classifiers)?
4. What's the minimum acceptable confidence threshold for local models?

---

**Status**: Proposal
**Author**: Claude Code
**Date**: 2025-03-26
**Related Issues**: External LLM dependency, offline scanning, cost optimization
