"""Training script for Peer-AI code review model."""

import json
import logging
from pathlib import Path
from typing import Optional

import torch
import yaml
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from trl import SFTTrainer


logger = logging.getLogger(__name__)


DEFAULT_CONFIG = {
    "model": {
        "name": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        "quantization": "4bit",
        "max_length": 4096,
    },
    "lora": {
        "r": 16,
        "alpha": 32,
        "dropout": 0.05,
        "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    },
    "training": {
        "output_dir": "models/peer-ai-reviewer",
        "epochs": 3,
        "batch_size": 4,
        "gradient_accumulation": 4,
        "learning_rate": 2e-4,
        "warmup_ratio": 0.03,
        "logging_steps": 10,
        "save_steps": 100,
        "eval_steps": 100,
    },
    "data": {
        "train_file": "data/train.jsonl",
        "eval_file": "data/eval.jsonl",
    },
}


def train_model(config_path: Optional[str] = None, resume_from: Optional[str] = None):
    """Fine-tune the code review model.
    
    Args:
        config_path: Path to training config YAML
        resume_from: Path to checkpoint to resume from
    """
    # Load config
    config = DEFAULT_CONFIG.copy()
    if config_path:
        with open(config_path) as f:
            user_config = yaml.safe_load(f)
            _deep_merge(config, user_config)
    
    logger.info(f"Training config: {json.dumps(config, indent=2)}")
    
    # Setup quantization
    bnb_config = None
    if config["model"]["quantization"] == "4bit":
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
    elif config["model"]["quantization"] == "8bit":
        bnb_config = BitsAndBytesConfig(load_in_8bit=True)
    
    # Load model and tokenizer
    logger.info(f"Loading model: {config['model']['name']}")
    
    tokenizer = AutoTokenizer.from_pretrained(config["model"]["name"])
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    model = AutoModelForCausalLM.from_pretrained(
        config["model"]["name"],
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True,
    )
    
    # Prepare for training
    if bnb_config:
        model = prepare_model_for_kbit_training(model)
    
    # Setup LoRA
    lora_config = LoraConfig(
        r=config["lora"]["r"],
        lora_alpha=config["lora"]["alpha"],
        lora_dropout=config["lora"]["dropout"],
        target_modules=config["lora"]["target_modules"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    
    # Load datasets
    logger.info("Loading training data...")
    train_data = _load_dataset(config["data"]["train_file"], tokenizer)
    eval_data = None
    if config["data"].get("eval_file") and Path(config["data"]["eval_file"]).exists():
        eval_data = _load_dataset(config["data"]["eval_file"], tokenizer)
    
    logger.info(f"Train samples: {len(train_data)}")
    if eval_data:
        logger.info(f"Eval samples: {len(eval_data)}")
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=config["training"]["output_dir"],
        num_train_epochs=config["training"]["epochs"],
        per_device_train_batch_size=config["training"]["batch_size"],
        gradient_accumulation_steps=config["training"]["gradient_accumulation"],
        learning_rate=config["training"]["learning_rate"],
        warmup_ratio=config["training"]["warmup_ratio"],
        logging_steps=config["training"]["logging_steps"],
        save_steps=config["training"]["save_steps"],
        eval_steps=config["training"]["eval_steps"] if eval_data else None,
        evaluation_strategy="steps" if eval_data else "no",
        fp16=True,
        optim="paged_adamw_8bit",
        report_to="wandb" if _wandb_available() else "none",
        save_total_limit=3,
        load_best_model_at_end=True if eval_data else False,
    )
    
    # Create trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=eval_data,
        tokenizer=tokenizer,
        dataset_text_field="text",
        max_seq_length=config["model"]["max_length"],
        packing=True,
    )
    
    # Train
    logger.info("Starting training...")
    trainer.train(resume_from_checkpoint=resume_from)
    
    # Save
    logger.info(f"Saving model to {config['training']['output_dir']}")
    trainer.save_model()
    tokenizer.save_pretrained(config["training"]["output_dir"])
    
    logger.info("Training complete!")


def _load_dataset(path: str, tokenizer) -> Dataset:
    """Load and format a JSONL dataset."""
    samples = []
    
    with open(path) as f:
        for line in f:
            data = json.loads(line)
            
            # Format as chat
            if "instruction" in data and "response" in data:
                text = _format_chat(data["instruction"], data["response"], tokenizer)
            elif "code" in data and "findings" in data:
                # Raw format - convert
                from peer_ai.model.data import format_for_training
                formatted = format_for_training(data)
                text = _format_chat(formatted["instruction"], formatted["response"], tokenizer)
            else:
                continue
            
            samples.append({"text": text})
    
    return Dataset.from_list(samples)


def _format_chat(instruction: str, response: str, tokenizer) -> str:
    """Format as chat template."""
    messages = [
        {"role": "user", "content": instruction},
        {"role": "assistant", "content": response},
    ]
    
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    else:
        # Fallback format
        return f"### Instruction:\n{instruction}\n\n### Response:\n{response}"


def _deep_merge(base: dict, override: dict):
    """Deep merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _wandb_available() -> bool:
    """Check if wandb is available and configured."""
    try:
        import wandb
        return wandb.api.api_key is not None
    except:
        return False
