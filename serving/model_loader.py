import json
import os
import re
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel


BASE_MODEL = os.getenv("XSS_AGENT_BASE_MODEL", "Qwen/Qwen2.5-Coder-3B-Instruct")
ADAPTER_DIR = os.getenv("XSS_AGENT_ADAPTER_DIR", "adapters/xss-agent-qwen3b-clean-peft")
DEVICE_MODE = os.getenv("XSS_AGENT_DEVICE", "cpu")  # auto | mps | cpu


SYSTEM_PROMPT = """You are XSSAgent, the dedicated model for Cross-Site Scripting scan decisions.
Return strict JSON only.
Your job is to decide whether the XSS plugin should run, plan validation inputs, filter false positives, and suggest the next scan action.
Use the requested JSON schema exactly."""


class XSSAgentModel:
    def __init__(self):
        self.device, self.dtype = self._select_device()

        print(f"[XSSAgentModel] base_model={BASE_MODEL}")
        print(f"[XSSAgentModel] adapter_dir={ADAPTER_DIR}")
        print(f"[XSSAgentModel] device={self.device}, dtype={self.dtype}")

        print("[XSSAgentModel] Loading tokenizer...")
        self.tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL,
            trust_remote_code=True,
        )

        print("[XSSAgentModel] Loading base model...")
        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            torch_dtype=self.dtype,
            trust_remote_code=True,
            low_cpu_mem_usage=True,
        )

        print("[XSSAgentModel] Loading PEFT adapter...")
        self.model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)

        print("[XSSAgentModel] Moving model to device...")
        self.model.to(self.device)
        self.model.eval()

        print("[XSSAgentModel] Model ready.")

    def _select_device(self):
        if DEVICE_MODE == "cpu":
            return "cpu", torch.float32

        if DEVICE_MODE == "mps":
            if not torch.backends.mps.is_available():
                raise RuntimeError("MPS requested but torch.backends.mps is not available.")
            return "mps", torch.float16

        # auto
        if torch.backends.mps.is_available():
            return "mps", torch.float16

        return "cpu", torch.float32

    def build_prompt(self, payload: dict) -> str:
        task = payload.get("task", "selection")

        user_prompt = f"""Task: {task}

Target:
- method: {payload.get("method", "GET")}
- url: {payload.get("url")}
- parameters: {payload.get("parameters", [])}
- response_sample: {payload.get("response_sample")}
- evidence: {payload.get("evidence", {})}

Return JSON only with this schema:
{{
  "task": "{task}",
  "should_run": true,
  "context_known": true,
  "confidence": 0.0,
  "reason": "short reason"
}}
"""

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        if hasattr(self.tokenizer, "apply_chat_template"):
            return self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        return SYSTEM_PROMPT + "\n\n" + user_prompt

    @staticmethod
    def extract_json(text: str) -> dict:
        match = re.search(r"\{.*\}", text.strip(), re.DOTALL)
        if not match:
            raise ValueError(f"No JSON object found in model output: {text[:300]}")
        return json.loads(match.group(0))

    def generate(self, payload: dict) -> dict:
        prompt = self.build_prompt(payload)

        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
        )

        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=160,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
                use_cache=True,
            )

        generated = outputs[0][inputs["input_ids"].shape[-1]:]
        text = self.tokenizer.decode(generated, skip_special_tokens=True)

        parsed = self.extract_json(text)
        parsed["raw_output"] = text
        return parsed
