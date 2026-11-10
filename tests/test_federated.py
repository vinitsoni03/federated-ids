import numpy as np
import torch

from federated_ids.attacks.poisoning import PoisonConfig, choose_malicious, poison_update, relabel_families
from federated_ids.data.ciciot import CLASS34, family_of_class34
from federated_ids.federated.aggregators import aggregate, fedavg, median, norm_clip, trimmed_mean
from federated_ids.federated.partition import make_partition, partition_stats
from federated_ids.models.mlp import MLP, flat_params, set_flat_params, train_epochs


def _y(n=5000, k=5, seed=0):
    return np.random.default_rng(seed).integers(0, k, n)


def test_partitions_cover_disjoint_and_skew_grows_as_alpha_shrinks():
    y = _y()
    for kind, alpha in [("iid", None), ("dirichlet", 1.0), ("dirichlet", 0.1)]:
        parts = make_partition(kind, y, 10, seed=3, alpha=alpha, min_size=10)
        allp = np.concatenate(parts)
        assert len(allp) == len(y) and len(np.unique(allp)) == len(y)
    tv = {a: partition_stats(make_partition("dirichlet", y, 10, 3, a, 10), y, 5)["mean_tv_distance"]
          for a in (100.0, 1.0, 0.1)}
    tv_iid = partition_stats(make_partition("iid", y, 10, 3), y, 5)["mean_tv_distance"]
    assert tv_iid < tv[100.0] + 0.05 and tv[100.0] < tv[1.0] < tv[0.1]
    a = make_partition("dirichlet", y, 10, 3, 0.5, 10)
    b = make_partition("dirichlet", y, 10, 3, 0.5, 10)
    assert all(np.array_equal(p, q) for p, q in zip(a, b))  # seeded => reproducible


def test_aggregators():
    U = torch.tensor([[1.0, 1.0], [1.0, 1.0], [1.0, 1.0], [100.0, -100.0]])
    w = torch.tensor([1.0, 1.0, 1.0, 1.0])
    assert torch.allclose(fedavg(U, torch.tensor([1.0, 0, 0, 0])), U[0])
    assert torch.allclose(median(U), torch.tensor([1.0, 1.0]))
    assert torch.allclose(trimmed_mean(U, beta=0.25), torch.tensor([1.0, 1.0]))
    assert norm_clip(U, w).norm() < 5   # the outlier was clipped to the median norm
    assert fedavg(U, w)[0] > 20          # plain FedAvg is dominated by the outlier
    assert torch.allclose(aggregate("median", U, w), median(U))


def test_poisoning_activation():
    d = torch.tensor([1.0, -2.0])
    assert torch.equal(poison_update(PoisonConfig(kind="none"), d, 10, 2), d)
    assert torch.equal(poison_update(PoisonConfig(kind="sign_flip", scale=5), d, 10, 2), -5 * d)
    assert torch.equal(poison_update(PoisonConfig(kind="label_flip_boost"), d, 10, 2), 5 * d)
    mal = choose_malicious(10, 0.2, seed=0)
    assert len(mal) == 2 and mal == choose_malicious(10, 0.2, seed=0)
    assert choose_malicious(10, 0.0, 0) == []
    fam = np.array(["Benign", "DDoS", "DoS", "DDoS"])
    assert relabel_families(np.array([0, 1, 1, 1]), fam, ["DDoS"], benign=0).tolist() == [0, 0, 1, 0]  # binary task
    assert relabel_families(np.array([0, 5, 9, 6]), fam, ["DDoS"], benign=0).tolist() == [0, 0, 9, 0]  # 34-class


def test_family_of_class34():
    fam = family_of_class34(np.arange(len(CLASS34)))
    assert fam[CLASS34.index("DDoS-SYN_Flood")] == "DDoS" and fam[CLASS34.index("Benign")] == "Benign"
    assert fam[CLASS34.index("Web-XSS")] == "Web" and (fam == "DDoS").sum() == 12


def test_fedprox_term_keeps_local_model_close():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(512, 4)).astype(np.float32)
    y = (X[:, 0] > 0).astype(int)
    dists = {}
    for mu in (0.0, 10.0):
        torch.manual_seed(0)
        m = MLP(4, 2, [8])
        g = flat_params(m)
        train_epochs(m, X, y, np.ones(2), 3, 0.05, 64, seed=0, prox_mu=mu, global_params=g)
        dists[mu] = float((flat_params(m) - g).norm())
    assert dists[10.0] < dists[0.0]


def test_flat_params_roundtrip():
    m = MLP(3, 2, [4])
    v = flat_params(m) + 1.0
    set_flat_params(m, v)
    assert torch.allclose(flat_params(m), v)
