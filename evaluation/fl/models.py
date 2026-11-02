"""Small models for MNIST-like data (CPU, single thread)."""

from __future__ import annotations

import numpy as np
import torch
from torch import nn


class LR(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.fc = nn.Linear(784, 10)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(x.flatten(1))


class MLP(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.Flatten(), nn.Linear(784, 128), nn.ReLU(), nn.Linear(128, 10))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class CNN(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.f = nn.Sequential(
            nn.Conv2d(1, 16, 5), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 5), nn.ReLU(), nn.MaxPool2d(2),
            nn.Flatten(), nn.Linear(32 * 4 * 4, 10),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.f(x)


MODELS = {"lr": LR, "mlp": MLP, "cnn": CNN}


def make(name: str, seed: int) -> nn.Module:
    torch.manual_seed(seed)
    return MODELS[name]()


def get_vector(model: nn.Module) -> np.ndarray:
    return torch.nn.utils.parameters_to_vector(model.parameters()).detach().numpy().astype(np.float32).copy()


def set_vector(model: nn.Module, vec: np.ndarray) -> None:
    torch.nn.utils.vector_to_parameters(torch.from_numpy(np.asarray(vec, dtype=np.float32)), model.parameters())


def train_local(model: nn.Module, x: torch.Tensor, y: torch.Tensor, epochs: int, batch: int, lr: float, seed: int) -> float:
    opt = torch.optim.SGD(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()
    g = torch.Generator().manual_seed(seed)
    model.train()
    total, count = 0.0, 0
    for _ in range(epochs):
        perm = torch.randperm(len(y), generator=g)
        for i in range(0, len(y), batch):
            idx = perm[i:i + batch]
            opt.zero_grad()
            loss = loss_fn(model(x[idx]), y[idx])
            loss.backward()
            opt.step()
            total += float(loss.detach()) * len(idx)
            count += len(idx)
    return total / max(1, count)


@torch.no_grad()
def evaluate(model: nn.Module, x: torch.Tensor, y: torch.Tensor, batch: int = 2000) -> tuple[float, float]:
    model.eval()
    loss_fn = nn.CrossEntropyLoss(reduction="sum")
    correct, loss = 0, 0.0
    for i in range(0, len(y), batch):
        out = model(x[i:i + batch])
        loss += float(loss_fn(out, y[i:i + batch]))
        correct += int((out.argmax(1) == y[i:i + batch]).sum())
    return correct / len(y), loss / len(y)
