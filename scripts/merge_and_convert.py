#!/usr/bin/env python3
"""Merge LoRA adapter with base model and prepare for GGUF conversion."""

import logging
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
ADAPTER_PATH = "models/peer-ai-reviewer"
OUTPUT_PATH = "models/peer-ai-merged"

def main():
    logger.info(f"Loading base model: {BASE_MODEL}")
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    
    logger.info(f"Loading tokenizer")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    
    logger.info(f"Loading LoRA adapter: {ADAPTER_PATH}")
    model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
    
    logger.info("Merging LoRA weights...")
    merged_model = model.merge_and_unload()
    
    logger.info(f"Saving merged model to: {OUTPUT_PATH}")
    merged_model.save_pretrained(OUTPUT_PATH, safe_serialization=True)
    tokenizer.save_pretrained(OUTPUT_PATH)
    
    logger.info("Done! Now convert to GGUF with:")
    logger.info(f"  python llama.cpp/convert_hf_to_gguf.py {OUTPUT_PATH} --outfile models/peer-ai.gguf --outtype q4_k_m")

if __name__ == "__main__":
    main()
