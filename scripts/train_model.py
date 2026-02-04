#!/usr/bin/env python3
"""Train the Peer-AI code review model."""

import json
import logging
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Workaround for bitsandbytes CUDA version
os.environ.setdefault("BNB_CUDA_VERSION", "130")


def load_dataset(path: str) -> Dataset:
    """Load JSONL dataset."""
    samples = []
    with open(path) as f:
        for line in f:
            data = json.loads(line)
            samples.append(data)
    return Dataset.from_list(samples)


def main():
    base_dir = Path(__file__).parent.parent
    data_dir = base_dir / "data"
    output_dir = base_dir / "models" / "peer-ai-reviewer"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Config
    model_name = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    max_length = 2048
    
    logger.info(f"Loading tokenizer: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    logger.info("Loading datasets...")
    train_data = load_dataset(data_dir / "train.jsonl")
    eval_data = load_dataset(data_dir / "eval.jsonl")
    
    def format_and_tokenize(example):
        """Format as chat and tokenize."""
        messages = [
            {"role": "user", "content": example["instruction"]},
            {"role": "assistant", "content": example["response"]},
        ]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        tokens = tokenizer(
            text,
            truncation=True,
            max_length=max_length,
            padding="max_length",
            return_tensors=None,
        )
        tokens["labels"] = tokens["input_ids"].copy()
        return tokens
    
    # Tokenize datasets
    train_data = train_data.map(format_and_tokenize, remove_columns=train_data.column_names)
    eval_data = eval_data.map(format_and_tokenize, remove_columns=eval_data.column_names)
    
    logger.info(f"Train: {len(train_data)}, Eval: {len(eval_data)}")
    
    # Quantization config
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    
    logger.info(f"Loading model: {model_name}")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True,
    )
    
    model = prepare_model_for_kbit_training(model)
    
    # LoRA config
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    
    # Training args
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=3,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        warmup_ratio=0.03,
        logging_steps=5,
        save_steps=50,
        eval_strategy="steps",
        eval_steps=50,
        fp16=True,
        optim="paged_adamw_8bit",
        report_to="none",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        remove_unused_columns=False,
    )
    
    # Data collator
    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False,
    )
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=eval_data,
        data_collator=data_collator,
    )
    
    logger.info("Starting training...")
    trainer.train()
    
    logger.info(f"Saving to {output_dir}")
    trainer.save_model()
    tokenizer.save_pretrained(output_dir)
    
    logger.info("Training complete!")


if __name__ == "__main__":
    main()
