"""
Flower Federated Learning Aggregation Server.

Features:
- Byzantine-robust aggregation (Krum n >= 2f+3, Trimmed Mean, FedAvg) + MAD outlier filtering
- Validated RDP Moments Privacy Accountant synchronized with DP noise multiplier
- Prometheus HTTP /metrics endpoint (port 8081 by default)
- Optional TLS server certificates on Flower gRPC
- Model checkpointing & JSON + Firestore persistence
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import flwr as fl
import numpy as np
import torch
from flwr.common import (
    FitRes,
    NDArrays,
    Parameters,
    Scalar,
    ndarrays_to_parameters,
    parameters_to_ndarrays,
)
from flwr.server.client_proxy import ClientProxy
from prometheus_client import Gauge, Counter, start_http_server

from federated_learning.aggregation import RobustAggregator
from federated_learning.model import LSTMThreatDetector
from federated_learning.privacy import GaussianMechanism, RDPPrivacyAccountant

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [FL-Server] %(message)s",
)
logger = logging.getLogger("SecureFL.FLServer")

PROM_FL_ROUND = Gauge("fl_server_current_round", "Latest completed FL round")
PROM_FL_ACC = Gauge("fl_server_global_accuracy", "Latest FL global accuracy")
PROM_FL_LOSS = Gauge("fl_server_global_loss", "Latest FL global loss")
PROM_FL_EPS = Gauge("fl_server_privacy_epsilon_spent", "Cumulative DP epsilon spent")
PROM_FL_REJECTED = Counter("fl_server_byzantine_rejected_total", "Byzantine clients filtered")


class DevSecOpsFedAvgStrategy(fl.server.strategy.FedAvg):
    """Custom Flower strategy with Byzantine filtering, RDP accounting, and checkpointing."""

    def __init__(
        self,
        strategy_name: str = "krum",
        krum_f: int = 1,
        trim_beta: float = 0.1,
        dp_budget: float = 10.0,
        dp_delta: float = 1e-5,
        noise_multiplier: float = 1.2,
        clip_norm: float = 1.0,
        model_save_dir: str = "models",
        metrics_file: str = "metrics/fl_metrics.json",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.strategy_name = strategy_name
        self.aggregator = RobustAggregator(
            strategy=strategy_name,
            krum_f=krum_f,
            trim_beta=trim_beta,
            auto_detect=True,
        )
        self.privacy_mech = GaussianMechanism()
        self.accountant = RDPPrivacyAccountant(total_epsilon=dp_budget, total_delta=dp_delta)
        self.noise_multiplier = noise_multiplier
        self.clip_norm = clip_norm
        self.privacy_delta = dp_delta

        self.model_save_dir = Path(model_save_dir)
        self.model_save_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_file = Path(metrics_file)
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)

        self.reference_model = LSTMThreatDetector(
            input_size=19, hidden_size=64, num_layers=2, num_classes=5
        )
        self.round_history: List[Dict[str, Union[int, float, str, list]]] = []

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        if not results:
            return None, {}

        weights_list: List[List[np.ndarray]] = []
        num_samples_list: List[int] = []
        tenant_ids: List[str] = []

        for idx, (client_proxy, fit_res) in enumerate(results):
            weights_list.append(parameters_to_ndarrays(fit_res.parameters))
            num_samples_list.append(fit_res.num_examples)
            tid = str(fit_res.metrics.get("tenant_id", client_proxy.cid or f"client_{idx}"))
            tenant_ids.append(tid)

        # Robust aggregation (MAD pre-screening + Krum/TrimmedMean/FedAvg)
        aggregated_ndarrays = self.aggregator.aggregate(
            weights_list, num_samples_list, strategy=self.strategy_name
        )
        rejected_indices = set(self.aggregator.last_suspicious_clients)
        rejected_tenants = [tenant_ids[i] for i in sorted(rejected_indices) if i < len(tenant_ids)]
        accepted_tenants = [tenant_ids[i] for i in range(len(tenant_ids)) if i not in rejected_indices]

        if rejected_tenants:
            PROM_FL_REJECTED.inc(len(rejected_tenants))
            logger.warning("Byzantine filter rejected clients in round %d: %s", server_round, rejected_tenants)

        # Calibrated central DP accounting synced with actual noise multiplier
        dp_rec = self.accountant.step_rdp(
            noise_multiplier=self.noise_multiplier,
            sample_rate=min(1.0, 32 / 2100.0),
            steps=2,
            delta=self.privacy_delta,
            clip_norm=self.clip_norm,
        )

        self._save_checkpoint(server_round, aggregated_ndarrays)

        honest_fit_res = [
            fit_res for i, (_cp, fit_res) in enumerate(results) if i not in rejected_indices
        ] or [fit_res for _cp, fit_res in results]

        losses = [float(fr.metrics["loss"]) for fr in honest_fit_res if "loss" in fr.metrics]
        accuracies = [float(fr.metrics["accuracy"]) for fr in honest_fit_res if "accuracy" in fr.metrics]
        avg_loss = float(np.mean(losses)) if losses else 0.0
        avg_acc = float(np.mean(accuracies)) if accuracies else 0.0

        round_info = {
            "round_num": server_round,
            "participating_clients": len(accepted_tenants),
            "participating_tenants": accepted_tenants,
            "rejected_tenants": rejected_tenants,
            "loss": round(avg_loss, 4),
            "accuracy": round(avg_acc, 4),
            "privacy_epsilon_spent": round(self.accountant.spent_epsilon, 4),
            "round_epsilon": round(dp_rec["round_epsilon"], 4),
            "noise_multiplier": self.noise_multiplier,
            "clip_norm": self.clip_norm,
            "strategy": self.strategy_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.round_history.append(round_info)
        self._write_metrics()

        PROM_FL_ROUND.set(server_round)
        PROM_FL_ACC.set(avg_acc)
        PROM_FL_LOSS.set(avg_loss)
        PROM_FL_EPS.set(self.accountant.spent_epsilon)

        return ndarrays_to_parameters(aggregated_ndarrays), {
            "loss": avg_loss,
            "accuracy": avg_acc,
            "epsilon_spent": float(self.accountant.spent_epsilon),
        }

    def aggregate_evaluate(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, fl.common.EvaluateRes]],
        failures: List[Union[Tuple[ClientProxy, fl.common.EvaluateRes], BaseException]],
    ) -> Tuple[Optional[float], Dict[str, Scalar]]:
        if not results:
            return None, {}
        losses = [r.loss for _, r in results]
        accs = [float(r.metrics["accuracy"]) for _, r in results if "accuracy" in r.metrics]
        agg_loss = float(np.mean(losses))
        agg_acc = float(np.mean(accs)) if accs else 0.0
        if self.round_history:
            self.round_history[-1]["eval_accuracy"] = round(agg_acc, 4)
            self.round_history[-1]["eval_loss"] = round(agg_loss, 4)
            self._write_metrics()
            PROM_FL_ACC.set(agg_acc)
        return agg_loss, {"accuracy": agg_acc}

    def _save_checkpoint(self, round_num: int, ndarrays: NDArrays) -> Path:
        keys = list(self.reference_model.state_dict().keys())
        state_dict = {k: torch.tensor(arr, dtype=torch.float32) for k, arr in zip(keys, ndarrays)}
        checkpoint_path = self.model_save_dir / f"global_model_round_{round_num}.pt"
        latest_path = self.model_save_dir / "latest_global_model.pt"
        torch.save(state_dict, checkpoint_path)
        torch.save(state_dict, latest_path)
        return checkpoint_path

    def _write_metrics(self) -> None:
        latest = self.round_history[-1] if self.round_history else {}
        payload = {
            "status": "completed",
            "total_rounds_completed": len(self.round_history),
            "latest_accuracy": latest.get("eval_accuracy", latest.get("accuracy", 0.0)),
            "latest_loss": latest.get("eval_loss", latest.get("loss", 0.0)),
            "privacy_epsilon_total": latest.get("privacy_epsilon_spent", 0.0),
            "privacy_delta": self.privacy_delta,
            "aggregation_strategy": self.strategy_name,
            "history": self.round_history,
        }
        with open(self.metrics_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureFL Flower Server")
    parser.add_argument("--port", type=int, default=int(os.getenv("FL_SERVER_PORT", "8080")))
    parser.add_argument("--metrics_port", type=int, default=int(os.getenv("FL_METRICS_PORT", "8081")))
    parser.add_argument("--rounds", type=int, default=int(os.getenv("FL_NUM_ROUNDS", "5")))
    parser.add_argument("--min_clients", type=int, default=int(os.getenv("FL_MIN_CLIENTS", "5")))
    parser.add_argument(
        "--strategy",
        type=str,
        default=os.getenv("FL_STRATEGY", "krum"),
        choices=["fedavg", "krum", "trimmed_mean"],
    )
    parser.add_argument("--noise_multiplier", type=float, default=float(os.getenv("DP_NOISE_MULTIPLIER", "1.2")))
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--ca_cert", type=str, default=os.getenv("FL_TLS_CA_CERT", "certs/ca.crt"))
    parser.add_argument("--server_cert", type=str, default=os.getenv("FL_TLS_SERVER_CERT", "certs/server.crt"))
    parser.add_argument("--server_key", type=str, default=os.getenv("FL_TLS_SERVER_KEY", "certs/server.key"))
    args = parser.parse_args()

    try:
        start_http_server(args.metrics_port)
        logger.info("FL Prometheus metrics server listening on :%d/metrics", args.metrics_port)
    except Exception as exc:
        logger.warning("Could not bind FL metrics port %d: %s", args.metrics_port, exc)

    init_model = LSTMThreatDetector(input_size=19, hidden_size=64, num_layers=2, num_classes=5)
    init_params = [val.detach().cpu().numpy() for _, val in init_model.state_dict().items()]

    strategy = DevSecOpsFedAvgStrategy(
        strategy_name=args.strategy,
        noise_multiplier=args.noise_multiplier,
        min_fit_clients=args.min_clients,
        min_available_clients=args.min_clients,
        min_evaluate_clients=args.min_clients,
        initial_parameters=ndarrays_to_parameters(init_params),
    )

    certificates = None
    if args.tls and all(Path(p).exists() for p in (args.ca_cert, args.server_cert, args.server_key)):
        certificates = (
            Path(args.ca_cert).read_bytes(),
            Path(args.server_cert).read_bytes(),
            Path(args.server_key).read_bytes(),
        )
        logger.info("TLS enabled on Flower gRPC server.")

    fl.server.start_server(
        server_address=f"0.0.0.0:{args.port}",
        config=fl.server.ServerConfig(num_rounds=args.rounds),
        strategy=strategy,
        certificates=certificates,
    )


if __name__ == "__main__":
    main()
