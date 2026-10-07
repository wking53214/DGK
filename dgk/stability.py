from __future__ import annotations

import hashlib
import math
import statistics
import time
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from .taxonomy import (
    REGIME_SEVERITY_INDEX,
    LyapunovWeightConfig,
    OperationalRegime,
    TelemetryCeilings,
    TelemetryMetricsPayload,
)

try:  # numpy powers the reservoir only; everything else is stdlib
    import numpy as np
except BaseException:  # pragma: no cover - environment dependent
    np = None


# STOCHASTIC TELEMETRY ANALYSIS & CONTROL THEORY ENERGY
# ============================================================
class RunningWelfordStatistics:
    """Tracks stable running data stats using numerically guarded online calculations."""

    def __init__(self) -> None:
        self.sample_count = 0
        self.running_mean = 0.0
        self.sum_of_squares = 0.0

    def process_sample(self, value: float) -> None:
        self.sample_count += 1
        deviation = value - self.running_mean
        self.running_mean += deviation / self.sample_count
        self.sum_of_squares += deviation * (value - self.running_mean)

    def calculate_standard_deviation(self) -> float:
        if self.sample_count < 2:
            return 1e-9
        return math.sqrt(self.sum_of_squares / (self.sample_count - 1))


class ThreadSafeSystemAnalytics:
    """Orchestrates asynchronous statistical updates across operational runtime paths."""

    def __init__(self) -> None:
        self.mutex_lock = Lock()
        self.metric_trackers = {
            "latency": RunningWelfordStatistics(),
            "abort": RunningWelfordStatistics(),
            "reentry": RunningWelfordStatistics(),
            "load": RunningWelfordStatistics(),
            "determinism": RunningWelfordStatistics(),
        }

    def register_payload(
        self, payload: TelemetryMetricsPayload
    ) -> Dict[str, Tuple[float, float]]:
        with self.mutex_lock:
            self.metric_trackers["latency"].process_sample(payload.latency)
            self.metric_trackers["abort"].process_sample(payload.abort_rate)
            self.metric_trackers["reentry"].process_sample(payload.reentry_rate)
            self.metric_trackers["load"].process_sample(payload.load_depth)
            self.metric_trackers["determinism"].process_sample(
                payload.determinism_index
            )
            return self.generate_snapshot()

    def generate_snapshot(self) -> Dict[str, Tuple[float, float]]:
        return {
            key: (tracker.running_mean, tracker.calculate_standard_deviation())
            for key, tracker in self.metric_trackers.items()
        }


def calculate_shannon_entropy(
    payload: TelemetryMetricsPayload, ceilings: TelemetryCeilings
) -> float:
    """Calculates systemic structural uncertainty based on entropy configurations."""
    distribution_probabilities = [
        payload.latency / ceilings.MAX_LATENCY_MS,
        payload.abort_rate,
        payload.reentry_rate / ceilings.MAX_REENTRY_RATE,
        payload.load_depth / ceilings.MAX_LOAD_DEPTH,
        payload.determinism_index,
    ]
    probability_sum = sum(distribution_probabilities)
    if probability_sum == 0:
        return 0.0
    entropy_accumulation = 0.0
    for probability in distribution_probabilities:
        if probability > 0:
            normalized_p = probability / probability_sum
            entropy_accumulation -= normalized_p * math.log2(normalized_p)
    return entropy_accumulation


def calculate_lyapunov_state_energy(
    payload: TelemetryMetricsPayload,
    stats: Dict[str, Tuple[float, float]],
    configuration: LyapunovWeightConfig,
) -> float:
    """Constructs dynamic quadratic bounds tracking system stability variance deviations."""

    def resolve_z_score(value, mean, std_dev):
        # With no established spread there is no basis for a z-score. The
        # original fell back to the raw magnitude, which treats a large-but-
        # normal metric as a large deviation: load_depth 280 became a z-score
        # of 280 and squared to dominate the whole energy sum. A value with no
        # measurable deviation from its own baseline contributes nothing.
        if std_dev <= 1e-6:
            return 0.0
        return (value - mean) / std_dev

    return (
        configuration.weight_latency
        * resolve_z_score(payload.latency, *stats["latency"]) ** 2
        + configuration.weight_abort
        * resolve_z_score(payload.abort_rate, *stats["abort"]) ** 2
        + configuration.weight_reentry
        * resolve_z_score(payload.reentry_rate, *stats["reentry"]) ** 2
        + configuration.weight_load
        * resolve_z_score(payload.load_depth, *stats["load"]) ** 2
        + configuration.weight_determinism
        * resolve_z_score(payload.determinism_index, *stats["determinism"]) ** 2
    )


class ControlTheoryRegimeClassifier:
    """Resolves operational severity buckets using control theory equations."""

    def __init__(self) -> None:
        self.analytics_orchestrator = ThreadSafeSystemAnalytics()

    def resolve_payload_regime(
        self, payload: TelemetryMetricsPayload
    ) -> Tuple[OperationalRegime, float, float]:
        historical_stats = self.analytics_orchestrator.register_payload(payload)
        ceilings_reference = TelemetryCeilings()
        computed_entropy = calculate_shannon_entropy(payload, ceilings_reference)
        computed_energy = calculate_lyapunov_state_energy(
            payload, historical_stats, LyapunovWeightConfig()
        )

        if payload.determinism_index > 0.85 and computed_energy > 3:
            return OperationalRegime.ANOMALOUS_DRIFT, computed_entropy, computed_energy
        if computed_entropy > 2.0:
            return (
                OperationalRegime.STOCHASTIC_CONFUSION,
                computed_entropy,
                computed_energy,
            )
        if payload.load_depth > 0.85 * ceilings_reference.MAX_LOAD_DEPTH:
            return (
                OperationalRegime.RESOURCE_SATURATED,
                computed_entropy,
                computed_energy,
            )

        latency_mean, latency_std = historical_stats["latency"]
        if payload.latency > latency_mean + 2 * latency_std:
            return OperationalRegime.TRANSIENT_SURGE, computed_entropy, computed_energy

        return OperationalRegime.NOMINAL, computed_entropy, computed_energy


class HysteresisControlChassis:
    """Dampens systemic oscillation flips across configuration boundaries."""

    def __init__(self, calm_readings_before_recovery: int = 3) -> None:
        self.classifier_engine = ControlTheoryRegimeClassifier()
        self.current_regime = OperationalRegime.NOMINAL
        self.calm_readings_before_recovery = max(1, calm_readings_before_recovery)
        self._calm_streak = 0
        self.mutex_lock = Lock()

    def process_telemetry_step(
        self, payload: TelemetryMetricsPayload
    ) -> Dict[str, Any]:
        """Escalate on the first bad reading, recover only after a sustained
        run of calmer ones.

        The recovered original could never recover at all. Its de-escalation
        branch required `self.current_regime == OperationalRegime.NOMINAL`, but
        NOMINAL is severity 1 -- the minimum -- so a strictly-lower resolved
        severity could not exist when that test was true. The branch was
        unreachable and the regime was a one-way ratchet: a system that spiked
        once stayed in the worse regime forever. See RECONSTRUCTION.md.
        """
        resolved_regime, entropy_metric, energy_metric = (
            self.classifier_engine.resolve_payload_regime(payload)
        )
        with self.mutex_lock:
            resolved_severity = REGIME_SEVERITY_INDEX[resolved_regime]
            current_severity = REGIME_SEVERITY_INDEX[self.current_regime]

            if resolved_severity > current_severity:
                self.current_regime = resolved_regime  # escalate at once
                self._calm_streak = 0
            elif resolved_severity < current_severity:
                self._calm_streak += 1
                if self._calm_streak >= self.calm_readings_before_recovery:
                    self.current_regime = resolved_regime  # sustained recovery
                    self._calm_streak = 0
            else:
                self._calm_streak = 0

        return {
            "operational_regime": self.current_regime.name,
            "entropy_value": entropy_metric,
            "lyapunov_energy": energy_metric,
        }


# ============================================================
# PIPELINE INTEGRATION & RECURRENT COMPUTATION LAYERS
# ============================================================
class EchoStateReservoir:
    """Provides high-dimensional state hashing matrices seeded via identity keys."""

    def __init__(self, seed_key: str, node_volume: int = 128):
        hashed_seed = int(hashlib.sha256(seed_key.encode()).hexdigest(), 16) % (2**32)
        np.random.seed(hashed_seed)
        self.node_volume = node_volume
        self.weight_recurrent = np.random.randn(node_volume, node_volume) * 0.05
        self.weight_input = np.random.randn(node_volume, 4) * 0.1
        self.state_vector = np.zeros(node_volume)
        self.weight_output = np.zeros((4, node_volume))

    def evaluate_step(self, input_vector: np.ndarray) -> np.ndarray:
        self.state_vector = np.tanh(
            self.weight_recurrent @ self.state_vector + self.weight_input @ input_vector
        )
        return self.state_vector

    def execute_training_batch(
        self, inputs_matrix: np.ndarray, targets_matrix: np.ndarray
    ) -> None:
        regularization_term = 1e-3
        augmented_inputs = np.hstack(
            [inputs_matrix, np.ones((inputs_matrix.shape[0], 1))]
        )
        self.weight_output = (
            np.linalg.pinv(
                augmented_inputs.T @ augmented_inputs
                + regularization_term * np.eye(augmented_inputs.shape[1])
            )
            @ augmented_inputs.T
            @ targets_matrix
        )
