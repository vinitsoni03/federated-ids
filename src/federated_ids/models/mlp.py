"""Compact MLP for tabular flow-window features, plus training helpers shared by the
centralized and federated experiments (local training with optional FedProx proximal term)."""
from __future__ import annotations

import numpy as np
import torch
from torch import nn


class MLP(nn.Module):
    def __init__(self, n_in: int, n_out: int, hidden: list[int] = (128, 64), dropout: float = 0.1):
        super().__init__()
        layers, d = [], n_in
        for h in hidden:
            layers += [nn.Linear(d, h), nn.ReLU(), nn.Dropout(dropout)]
            d = h
        layers.append(nn.Linear(d, n_out))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def set_seed(seed: int) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def resolve_device(name: str = "auto") -> torch.device:
    """'auto' -> cuda if available else cpu. On CUDA, deterministic algorithms are requested
    (CUBLAS_WORKSPACE_CONFIG must be set before CUDA initialises; done here if missing)."""
    import os

    if name == "auto":
        name = "cuda" if torch.cuda.is_available() else "cpu"
    dev = torch.device(name)
    if dev.type == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("device 'cuda' requested but torch.cuda.is_available() is False")
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
        torch.use_deterministic_algorithms(True, warn_only=True)
    return dev


def as_tensor(X, device: torch.device, dtype=torch.float32) -> torch.Tensor:
    if isinstance(X, torch.Tensor):
        return X.to(device=device, dtype=dtype)
    return torch.as_tensor(np.ascontiguousarray(X), dtype=dtype, device=device)


def class_weights(y: np.ndarray, n_classes: int, scheme: str = "sqrt_inverse") -> np.ndarray:
    """Loss weights from label counts; absent classes get weight 0. Mean weight over present
    classes is normalised to 1."""
    counts = np.bincount(y, minlength=n_classes).astype(np.float64)
    w = np.zeros(n_classes)
    present = counts > 0
    if scheme == "none":
        w[present] = 1.0
    elif scheme == "inverse":
        w[present] = counts[present].sum() / counts[present]
    elif scheme == "sqrt_inverse":
        w[present] = np.sqrt(counts[present].sum() / counts[present])
    else:
        raise ValueError(scheme)
    w[present] /= w[present].mean()
    return w


def flat_params(model: nn.Module) -> torch.Tensor:
    return torch.cat([p.detach().reshape(-1) for p in model.parameters()]).clone()


def set_flat_params(model: nn.Module, vec: torch.Tensor) -> None:
    i = 0
    with torch.no_grad():
        for p in model.parameters():
            n = p.numel()
            p.copy_(vec[i:i + n].view_as(p))
            i += n


def train_epochs(model: nn.Module, X, y, weights: np.ndarray, epochs: int,
                 lr: float, batch_size: int, seed: int, prox_mu: float = 0.0,
                 global_params: torch.Tensor | None = None, optimizer: str = "adam",
                 label_map: np.ndarray | None = None) -> float:
    """Train in place on the model's device; returns mean loss of the last epoch.
    X, y: numpy arrays or tensors. prox_mu > 0 adds the FedProx term (mu/2)||w - w_global||^2.
    label_map optionally relabels y (used by label-flip poisoning). Shuffles are drawn on the
    CPU from `seed`, so the batch order is identical on CPU and GPU."""
    dev = next(model.parameters()).device
    g = torch.Generator().manual_seed(seed)
    Xt = as_tensor(X, dev)
    y_np = y.cpu().numpy() if isinstance(y, torch.Tensor) else np.asarray(y)
    yt = torch.as_tensor((label_map[y_np] if label_map is not None else y_np).astype(np.int64), device=dev)
    crit = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=dev))
    opt = (torch.optim.Adam(model.parameters(), lr=lr) if optimizer == "adam"
           else torch.optim.SGD(model.parameters(), lr=lr, momentum=0.9))
    model.train()
    last = 0.0
    for _ in range(epochs):
        perm = torch.randperm(len(yt), generator=g).to(dev)
        tot, nb = torch.zeros((), device=dev), 0
        for s in range(0, len(perm), batch_size):
            b = perm[s:s + batch_size]
            opt.zero_grad()
            loss = crit(model(Xt[b]), yt[b])
            if prox_mu > 0 and global_params is not None:
                loss = loss + 0.5 * prox_mu * torch.sum((torch.cat([p.reshape(-1) for p in model.parameters()])
                                                         - global_params) ** 2)
            loss.backward()
            opt.step()
            tot += loss.detach()  # stays on device: no per-batch GPU sync
            nb += 1
        last = float(tot) / max(nb, 1)
    return last


@torch.no_grad()
def predict_proba(model: nn.Module, X, batch_size: int = 65536) -> np.ndarray:
    model.eval()
    dev = next(model.parameters()).device
    out = []
    for s in range(0, len(X), batch_size):
        xb = as_tensor(X[s:s + batch_size], dev)
        out.append(torch.softmax(model(xb), dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.empty((0, 0))
