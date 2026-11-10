# Threat models (defined before the experiments were run)

The project studies four related but **distinct** problems. They are evaluated separately; no
single dataset or experiment is claimed to cover all four. All experiments are offline
simulations on recorded datasets; no traffic is sent to any real system.

| | A. Conventional IoT intrusion | B. Federated model-update poisoning | C. Inference-time evasion | D. LLM-coordinated attacks |
|---|---|---|---|---|
| Dataset | CICIoT2023 | CICIoT2023 (FL simulation) | CICIoT2023 (trained IDS) | GridStratLLM |
| Who is the adversary | attacker generating network attacks | some federated clients | attacker shaping its own attack traffic | LLM agents planning MITM/data-modification attacks |
| Target | IDS accuracy | the global model's training | a trained, fixed IDS | smart-grid process + its monitoring |
| Milestone | M4/M5 | M6 | M7 | M8 |

## A. Detection task (M4, M5)
Window-level multi-class classification of CICIoT2023 feature windows into Benign + 7 attack
families (main task) and 34 classes (supplementary). The defender trains on labelled windows. No
adversarial manipulation of training or test data in A.

## B. Federated model-update poisoning (M6)
* **System:** K = 10 clients, every client participates in every round, FedAvg-style server that
  aggregates parameter deltas; local training identical to the clean FL baseline.
* **Attacker capability:** controls m of K clients (m/K = 0.1, 0.2, 0.3; fixed, seeded choice).
  Malicious clients hold their own honest partition of real training data, receive the global model
  each round (white-box on the current model), know the protocol and the aggregation rule, and may
  submit an arbitrary update vector. They **cannot** read honest clients' data or updates
  (non-omniscient), tamper with the server, or change other clients' messages. No collusion beyond
  using the same attack rule.
* **Attacks:**
  1. *Untargeted sign-flip* (`sign_flip`): submit -5 x (own honest delta). Objective: lower global
     macro-F1 / raise errors for everyone.
  2. *Targeted label-flip with boosting* (`label_flip_boost`): relabel the client's own **DDoS**
     rows as Benign, train, submit (K/m) x delta (model-replacement-style boosting, Bagdasaryan et
     al., 2020). Objective: global model labels DDoS windows as Benign (stealthy false negatives)
     while other classes keep working. Success = fraction of DDoS test windows predicted Benign.
* **Defences evaluated:** coordinate-wise median and trimmed mean (beta = 0.2) (Yin et al., 2018),
  norm clipping to the per-round median update norm (cf. Sun et al., 2019). Assumptions: m < K/2
  for median; beta >= m/K for trimmed mean (holds for m/K <= 0.2; deliberately violated at 0.3 to
  show the boundary). Robust rules ignore self-reported sample counts.
* **Measured:** clean utility of each aggregator without attack, macro-F1/FPR under attack,
  per-class impact, target evasion rate, wall-clock time, communication volume.

## C. Inference-time evasion (M7)
* **Target:** the trained centralized IDS (MLP seed 0; also a Random Forest), fixed after training.
* **Goal:** a currently detected attack window is classified **Benign** (relabelling to a different
  attack class does not count).
* **Access:** black-box, label-only queries; query budget = search grid (<= 112 queries/window).
* **Capabilities (attacker's own packets only), with consistent feature recomputation:**
  payload padding p in {0..1450} bytes (Min/Max/AVG/Tot size + p, Std/Variance unchanged, Max + p <= 1514);
  rate reduction r in {1, 0.5, 0.25, 0.1} (Rate x r, IAT / r); TTL set to a benign-typical value
  (10/50/90 % quantiles of benign train TTL).
* **Not allowed:** changing protocol indicators, flag ratios/counts, Protocol Type, Header_Length
  (would change the attack itself), touching benign traffic, or modifying the model.
* **Cost:** every r < 1 cuts the attack's packet rate; results are reported per budget r_min.
* **Validity checks:** each successful adversarial window is re-checked against the constraints
  (`check_constraints`, zero violations required) and re-queried.
* **Limitation:** perturbations are modelled in feature space from the feature definitions; they
  were not replayed as packets through the CIC feature extractor.

## D. LLM-coordinated attacks (M8)
* **Data:** GridStratLLM HIL captures; attacks planned by four LLMs (5 attack datasets) and executed
  by attack workers through ARP MITM and S7/Modbus data modification.
* **Question:** do network-observable signatures learned from sessions planned by some LLMs
  transfer to sessions planned by a held-out LLM? At what false-alarm rate on normal operation?
* **Ground truth:** session activity intervals from `attack_exec_steps`; no assumption-based labels.
* **Defender knowledge:** identity-free window statistics (no MAC/IP values) + Zeek weird events.
* This is not a generic IoT result: the testbed is an industrial (S7/Modbus) smart-grid network.
