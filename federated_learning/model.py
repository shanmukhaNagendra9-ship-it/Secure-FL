"""
PyTorch neural models for multi-tenant cloud threat detection via federated learning.

Fixed:
- INPUT_SIZE aligned to 19 engineered telemetry features (matching data_simulator.FEATURE_COLUMNS)
- AutoencoderDetector output uses linear projection (compatible with StandardScaler features)
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch.utils.data import DataLoader

logger = logging.getLogger("SecureFL.Models")


class ThreatLabel(Enum):
    NORMAL = 0
    BRUTE_FORCE = 1
    DATA_EXFIL = 2
    PRIVILEGE_ESC = 3
    LATERAL_MOVE = 4

    @classmethod
    def num_classes(cls) -> int:
        return len(cls)

    @classmethod
    def from_index(cls, idx: int) -> "ThreatLabel":
        for member in cls:
            if member.value == idx:
                return member
        raise ValueError(f"No ThreatLabel with index {idx}")


class LSTMThreatDetector(nn.Module):
    """Stacked LSTM classifier for cloud telemetry sequences (19 input features, 5 classes)."""

    INPUT_SIZE = 19
    HIDDEN_SIZE = 64
    NUM_LAYERS = 2
    NUM_CLASSES = 5
    DROPOUT = 0.3

    def __init__(
        self,
        input_size: int = INPUT_SIZE,
        hidden_size: int = HIDDEN_SIZE,
        num_layers: int = NUM_LAYERS,
        num_classes: int = NUM_CLASSES,
        dropout: float = DROPOUT,
    ) -> None:
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.num_classes = num_classes

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=False,
        )
        self.layer_norm = nn.LayerNorm(hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes),
        )
        self._init_weights()

    def _init_weights(self) -> None:
        for name, param in self.lstm.named_parameters():
            if "weight_ih" in name:
                nn.init.xavier_uniform_(param.data)
            elif "weight_hh" in name:
                nn.init.orthogonal_(param.data)
            elif "bias" in name:
                param.data.fill_(0)
                n = param.size(0)
                param.data[n // 4:n // 2].fill_(1)

        for layer in self.classifier:
            if isinstance(layer, nn.Linear):
                nn.init.xavier_uniform_(layer.weight)
                nn.init.zeros_(layer.bias)

    def forward(self, x: Tensor) -> Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        lstm_out, _ = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]
        normed = self.layer_norm(last_hidden)
        dropped = self.dropout(normed)
        return self.classifier(dropped)

    def training_step(
        self,
        batch: Tuple[Tensor, Tensor],
        optimizer: torch.optim.Optimizer,
        criterion: Optional[nn.Module] = None,
    ) -> Dict[str, float]:
        if criterion is None:
            criterion = nn.CrossEntropyLoss()
        self.train()
        features, labels = batch
        optimizer.zero_grad()
        logits = self.forward(features)
        loss = criterion(logits, labels.long())
        loss.backward()
        nn.utils.clip_grad_norm_(self.parameters(), max_norm=1.0)
        optimizer.step()
        with torch.no_grad():
            preds = logits.argmax(dim=-1)
            accuracy = (preds == labels.long()).float().mean().item()
        return {"loss": float(loss.item()), "accuracy": float(accuracy)}

    @torch.no_grad()
    def evaluate(
        self,
        data_loader: DataLoader,
        criterion: Optional[nn.Module] = None,
        device: Optional[torch.device] = None,
    ) -> Dict[str, object]:
        if criterion is None:
            criterion = nn.CrossEntropyLoss()
        if device is None:
            device = next(self.parameters()).device

        self.eval()
        total_loss = 0.0
        correct = 0
        total_samples = 0
        class_correct = torch.zeros(self.num_classes)
        class_total = torch.zeros(self.num_classes)

        for features, labels in data_loader:
            features = features.to(device)
            labels = labels.to(device).long()
            logits = self.forward(features)
            loss = criterion(logits, labels)
            total_loss += loss.item() * features.size(0)
            preds = logits.argmax(dim=-1)
            correct += (preds == labels).sum().item()
            total_samples += features.size(0)
            for c in range(self.num_classes):
                mask = labels == c
                class_correct[c] += (preds[mask] == labels[mask]).sum().item()
                class_total[c] += mask.sum().item()

        avg_loss = total_loss / max(total_samples, 1)
        accuracy = correct / max(total_samples, 1)
        per_class = {
            ThreatLabel.from_index(c).name: (
                class_correct[c].item() / max(class_total[c].item(), 1)
            )
            for c in range(self.num_classes)
        }
        return {
            "loss": avg_loss,
            "accuracy": accuracy,
            "per_class_accuracy": per_class,
            "num_samples": total_samples,
        }


class AutoencoderDetector(nn.Module):
    """
    1D Convolutional Autoencoder for reconstruction-error anomaly scoring on 19-feature vectors.
    Uses a linear output layer so reconstructions match standardized (zero-mean) features.
    """

    INPUT_SIZE = 19
    ENCODING_DIM = 8

    def __init__(
        self,
        input_size: int = INPUT_SIZE,
        encoding_dim: int = ENCODING_DIM,
    ) -> None:
        super().__init__()
        self.input_size = input_size
        self.encoding_dim = encoding_dim

        self.encoder = nn.Sequential(
            nn.Conv1d(1, 16, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(16),
            nn.ReLU(inplace=True),
            nn.Conv1d(16, 32, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(32),
            nn.ReLU(inplace=True),
        )
        self._enc_flat = self._compute_enc_flat(input_size)
        self.enc_fc = nn.Linear(self._enc_flat, encoding_dim)
        self.dec_fc = nn.Linear(encoding_dim, self._enc_flat)

        # Linear output head (no Sigmoid) so StandardScaler features in R are reconstructed faithfully
        self.decoder = nn.Sequential(
            nn.ConvTranspose1d(32, 16, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm1d(16),
            nn.ReLU(inplace=True),
            nn.ConvTranspose1d(16, 1, kernel_size=3, stride=2, padding=1, output_padding=1),
        )
        self._init_weights()

    def _compute_enc_flat(self, input_size: int) -> int:
        with torch.no_grad():
            dummy = torch.zeros(1, 1, input_size)
            out = self.encoder(dummy)
            self._enc_channels = out.shape[1]
            self._enc_len = out.shape[2]
            return out.numel()

    def _init_weights(self) -> None:
        for m in self.modules():
            if isinstance(m, (nn.Conv1d, nn.ConvTranspose1d)):
                nn.init.kaiming_normal_(m.weight, mode="fan_out", nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                nn.init.zeros_(m.bias)
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.ones_(m.weight)
                nn.init.zeros_(m.bias)

    def encode(self, x: Tensor) -> Tensor:
        h = self.encoder(x).view(x.size(0), -1)
        return self.enc_fc(h)

    def decode(self, z: Tensor) -> Tensor:
        h = self.dec_fc(z).view(z.size(0), self._enc_channels, self._enc_len)
        x_hat = self.decoder(h)
        if x_hat.shape[-1] < self.input_size:
            x_hat = F.pad(x_hat, (0, self.input_size - x_hat.shape[-1]))
        return x_hat[:, :, : self.input_size]

    def forward(self, x: Tensor) -> Tuple[Tensor, Tensor]:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        z = self.encode(x)
        x_hat = self.decode(z)
        return x_hat, z

    @torch.no_grad()
    def anomaly_score(self, x: Tensor) -> Tensor:
        self.eval()
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x_hat, _ = self.forward(x)
        return F.mse_loss(x_hat, x, reduction="none").mean(dim=[1, 2])


def get_model(model_type: str, **kwargs) -> nn.Module:
    mt = model_type.strip().lower()
    if mt in ("lstm", "lstmthreatdetector"):
        return LSTMThreatDetector(**kwargs)
    if mt in ("autoencoder", "ae", "autoencoderdetector"):
        return AutoencoderDetector(**kwargs)
    raise ValueError(f"Unknown model_type '{model_type}'. Choose 'lstm' or 'autoencoder'.")
