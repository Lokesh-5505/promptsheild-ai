import json
import time
import os
from typing import Dict, Any, List
from src.pipeline.detector import PromptInjectionDetector
from src.pipeline.rule_engine import RuleEngine
from src.pipeline.classifier import DistilBertClassifier

def run_evaluation(benchmark_file: str = "data/test.csv") -> Dict[str, Any]:
    if not os.path.exists(benchmark_file):
        # Fallback to test.csv if benchmark_test.jsonl passed but doesn't exist
        alt_path = "data/test.csv"
        if os.path.exists(alt_path):
            benchmark_file = alt_path
        else:
            raise FileNotFoundError(f"Benchmark file {benchmark_file} does not exist.")

    samples = []
    if benchmark_file.endswith(".csv"):
        import pandas as pd
        df = pd.read_csv(benchmark_file)
        samples = df.to_dict(orient="records")
    else:
        with open(benchmark_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    samples.append(json.loads(line))

    # Initialize systems
    detector = PromptInjectionDetector()
    rule_engine = RuleEngine()
    classifier = DistilBertClassifier()

    def eval_system(system_name: str, predict_fn):
        tp, fp, tn, fn = 0, 0, 0, 0
        latencies = []

        for item in samples:
            text = item["text"]
            is_inj = item["is_injection"]

            t0 = time.perf_counter()
            pred_inj = predict_fn(text, item["source_type"])
            lat_ms = (time.perf_counter() - t0) * 1000
            latencies.append(lat_ms)

            if is_inj and pred_inj:
                tp += 1
            elif not is_inj and pred_inj:
                fp += 1
            elif not is_inj and not pred_inj:
                tn += 1
            elif is_inj and not pred_inj:
                fn += 1

        total_inj = tp + fn
        total_ben = tn + fp

        recall = round((tp / total_inj * 100) if total_inj > 0 else 0.0, 1)
        fpr = round((fp / total_ben * 100) if total_ben > 0 else 0.0, 1)
        precision = round((tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0, 1)
        
        prec_dec = precision / 100.0
        rec_dec = recall / 100.0
        f1 = round((2 * prec_dec * rec_dec / (prec_dec + rec_dec)) if (prec_dec + rec_dec) > 0 else 0.0, 3)

        latencies.sort()
        p50 = round(latencies[len(latencies) // 2], 2)
        p95 = round(latencies[int(len(latencies) * 0.95)], 2)

        return {
            "system": system_name,
            "samples": len(samples),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "recall": recall,
            "fpr": fpr,
            "precision": precision,
            "f1": f1,
            "p50_ms": p50,
            "p95_ms": p95,
        }

    # 1. Rules-Only
    def rules_predict(text, src):
        matches = rule_engine.scan(text)
        return len(matches) > 0

    # 2. Model-Only
    def model_predict(text, src):
        res = classifier.predict(text)
        return res.is_malicious

    # 3. Hybrid Pipeline
    def hybrid_predict(text, src):
        res = detector.analyze(text, source_type=src)
        return res["decision"] in ["flag", "review", "block"]

    results = {
        "rules_only": eval_system("Rules-Only Baseline", rules_predict),
        "model_only": eval_system("Model-Only Baseline", model_predict),
        "hybrid_pipeline": eval_system("PromptShield Hybrid Pipeline", hybrid_predict),
    }

    return results

if __name__ == "__main__":
    report = run_evaluation()
    print("\n================== BENCHMARK EVALUATION REPORT ==================")
    for k, v in report.items():
        print(f"\n[{v['system']}]")
        print(f"  Recall (Injections caught): {v['recall']}%")
        print(f"  False Positive Rate (FPR): {v['fpr']}%")
        print(f"  Macro F1-Score:             {v['f1']}")
        print(f"  P95 Latency (CPU):          {v['p95_ms']} ms")
