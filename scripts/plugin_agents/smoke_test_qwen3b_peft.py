import json
import re
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

BASE_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"
ADAPTER_DIR = "adapters/xss-agent-qwen3b-clean-peft"

SYSTEM_PROMPT = """You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions.
Return strict JSON only.
You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees.
Your job is to decide whether the S2N xss plugin should run, plan context-aware authorized scanner validation inputs, filter false positives, and suggest the next scan action.
Use the requested JSON schema exactly."""

USER_PROMPT = """Task: selection

Target:
- method: GET
- url: http://127.0.0.1:5000/search?q=test
- parameters: ["q"]
- response_sample: "<html><body><p>You searched for: test</p></body></html>"
- reflection: true
- reflected_params: ["q"]

Return JSON only with this schema:
{
  "task": "selection",
  "should_run": true,
  "context_known": true,
  "confidence": 0.0,
  "reason": "short reason"
}
"""

def extract_json(text: str):
    text = text.strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in model output")
    return json.loads(match.group(0))

def main():
    print("[1] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)

    print("[2] Loading base model...")
    if torch.backends.mps.is_available():
        device = "mps"
        dtype = torch.float16
    else:
        device = "cpu"
        dtype = torch.float32

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=dtype,
        trust_remote_code=True,
    )

    print("[3] Loading PEFT adapter...")
    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.to(device)
    model.eval()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ]

    if hasattr(tokenizer, "apply_chat_template"):
        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
    else:
        prompt = SYSTEM_PROMPT + "\n\n" + USER_PROMPT

    print("[4] Running inference...")
    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=False,
            temperature=0.0,
            pad_token_id=tokenizer.eos_token_id,
        )

    generated = outputs[0][inputs["input_ids"].shape[-1]:]
    text = tokenizer.decode(generated, skip_special_tokens=True)

    print("\n===== RAW MODEL OUTPUT =====")
    print(text)

    print("\n===== JSON PARSE TEST =====")
    parsed = extract_json(text)
    print(json.dumps(parsed, ensure_ascii=False, indent=2))

    required = ["task", "should_run", "context_known", "confidence", "reason"]
    missing = [k for k in required if k not in parsed]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

    print("\n✅ PEFT adapter smoke test passed.")

if __name__ == "__main__":
    main()
