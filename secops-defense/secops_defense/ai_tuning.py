"""AI Tuning Module for SecOps Detection

This module provides a heuristic simulation of an AI detection tuning model.
It adjusts detection thresholds based on historical false-positive feedbacks
to reduce alert fatigue.
"""

import json
import os

FEEDBACK_STORE = os.path.expanduser("~/.secops_ai_feedback.json")

class AITuningModule:
    def __init__(self, base_sensitivity: int = 50):
        """
        :param base_sensitivity: Base sensitivity score (0-100). Higher means more sensitive (lower thresholds).
        """
        self.base_sensitivity = base_sensitivity
        self.feedback_data = self._load_feedback()

    def _load_feedback(self) -> dict:
        if os.path.exists(FEEDBACK_STORE):
            try:
                with open(FEEDBACK_STORE, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_feedback(self):
        try:
            with open(FEEDBACK_STORE, 'w') as f:
                json.dump(self.feedback_data, f)
        except Exception as e:
            print(f"[!] Warning: failed to save AI tuning feedback - {e}")

    def report_feedback(self, rule_id: str, is_false_positive: bool):
        """Report a false positive or true positive to adjust future sensitivity."""
        if rule_id not in self.feedback_data:
            self.feedback_data[rule_id] = {"fp": 0, "tp": 0}
        
        if is_false_positive:
            self.feedback_data[rule_id]["fp"] += 1
        else:
            self.feedback_data[rule_id]["tp"] += 1
            
        self._save_feedback()

    def tune_threshold(self, rule_id: str, default_threshold: int) -> int:
        """
        Automatically calculate the optimal threshold based on feedback.
        If FP is high, increase threshold (make it less sensitive).
        """
        stats = self.feedback_data.get(rule_id, {"fp": 0, "tp": 0})
        fp_rate = 0
        total = stats["fp"] + stats["tp"]
        
        if total > 0:
            fp_rate = stats["fp"] / total
            
        # Example heuristic: if FP rate > 50%, increase threshold by up to 100%
        # if FP rate is 0, we can keep the default.
        adjustment_factor = 1.0 + (fp_rate * 1.5) 
        
        # Base sensitivity also affects the threshold (higher sensitivity = lower threshold)
        sensitivity_multiplier = (100 - self.base_sensitivity) / 50.0 # 50 is normal (x1.0), 100 is highly sensitive (x0.0)
        if sensitivity_multiplier < 0.5:
            sensitivity_multiplier = 0.5
            
        new_threshold = int(default_threshold * adjustment_factor * sensitivity_multiplier)
        # Ensure it doesn't drop below a minimum bound
        return max(1, new_threshold)

def get_tuned_threshold(rule_id: str, default_threshold: int, sensitivity: int = 50) -> int:
    """Helper function to quickly get a tuned threshold."""
    tuner = AITuningModule(base_sensitivity=sensitivity)
    return tuner.tune_threshold(rule_id, default_threshold)
