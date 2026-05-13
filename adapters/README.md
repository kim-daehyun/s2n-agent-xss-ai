# PEFT Adapters

This directory is intentionally kept out of normal Git tracking because PEFT
adapter weights are large and may exceed GitHub's regular file-size limits.

The distribution workflow expects users to place an adapter directory here
before running the default Docker smoke tests. For example:

```text
adapters/
  xss-agent-qwen3b-clean-peft/
    adapter_config.json
    adapter_model.safetensors
    tokenizer.json
    tokenizer_config.json
```

Then run the URL-to-PDF tool with:

```bash
--use-peft-agent --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

The normal Docker command uses `--use-peft-agent`. If the adapter is missing or
incomplete, the run fails early with a clear error. Use `--no-peft-agent` only
for explicit rule-based debugging.

Recommended setup:

```bash
bash scripts/download_peft_adapter.sh
```

Default Hugging Face adapter repo:

```text
emmaemmaemma123/xss-agent-qwen3b-clean-peft
```
