---
title: "Literature Review"
subtitle: "AI-Enabled Cyberattack Detection and Adversarially Robust Federated Intrusion Detection"
author: "Vinit Soni (E23CSEU0437), Bennett University"
date: "13 November 2026"
---

# 1. Purpose and scope

This review sets out the existing work behind the project, compares it in detail with the closest published studies, and states the gap that the project addresses. It replaces the six-source Phase 1 survey (16 October 2026). The project's own experiments have been run since then, so the comparison is now **between published results and measured results**, not only between published descriptions.

**How the sources were chosen.**

* **Core sources (read in full).** The four papers the project builds on directly: Neto et al. (2023, the CICIoT2023 dataset paper), Bilal et al. (2026), Nayak and Reddy (2026), and Kampourakis et al. (2026). The full texts were read for this review, and every number quoted from them below comes from their own tables.
* **Dataset sources.** The GridStratLLM dataset record and conference paper (Kellerer and Hagenmeyer, 2026a, 2026b).
* **Foundational methods.** The methods the project actually implements: FedAvg, FedProx, the Dirichlet non-IID protocol, Byzantine-robust aggregation, backdoor and boosting attacks, problem-space evasion and the methodological pitfalls of ML in security. Each entry was checked against its publisher, proceedings or arXiv record.
* **Secondary sources.** A small number of methods mentioned only for context (Krum, FLTrust, FedNova, Edge-IIoTset). Their details are cited as described by the core papers that use them.

This is a focused review, not a systematic one. It covers the sources that bear on the project's five research questions.

# 2. Background

## 2.1 Intrusion detection for IoT

A network intrusion detection system (NIDS) watches traffic and raises alerts for attacks. Machine-learning NIDS learn the difference between benign and malicious traffic from labelled examples, usually as flow or window statistics (packet counts, sizes, inter-arrival times, protocol flags). IoT networks make this harder for three reasons: devices are numerous and heterogeneous, much of their traffic is low-rate and repetitive, and they are a favourite target for botnets such as Mirai (Neto et al., 2023).

## 2.2 Federated learning

In federated learning (FL), clients train a shared model on their own data and send only model updates to a server, which aggregates them. FedAvg averages the client models weighted by data size (McMahan et al., 2017). FedProx adds a proximal term that keeps each client's local model close to the global one, which is meant to help when clients' data differ (Li et al., 2020). Heterogeneity is usually simulated by giving each client a class mix drawn from a Dirichlet distribution with concentration α; small α means strong label skew (Hsu et al., 2019).

For intrusion detection, FL is attractive because raw traffic can stay inside each site. It also opens a new attack surface: a client can send a manipulated update.

## 2.3 Two different attacks on a learned detector

* **Model-update poisoning** attacks training. A malicious FL client sends updates that degrade the global model (untargeted, e.g. sign-flipping) or make it misclassify a chosen class (targeted, e.g. DDoS labelled as benign, made stronger by boosting the update; Bagdasaryan et al., 2020; Sun et al., 2019). Byzantine-robust aggregators such as the coordinate-wise median and trimmed mean limit the influence of a bounded fraction of malicious clients (Yin et al., 2018).
* **Inference-time evasion** attacks the deployed model. The attacker changes its own traffic so that the detector labels it benign. For a NIDS the change must be realisable: the attacker can pad packets, slow down or change header fields of its own traffic, but cannot change the victim's traffic or the feature extractor (Apruzzese et al., 2022; Pierazzi et al., 2020).

These two threats need separate threat models and separate experiments.

## 2.4 "AI-enabled" attacks

The phrase covers two different things in the literature:

1. **Attacks planned or executed by AI agents.** GridStratLLM records cyberattacks on a hardware-in-the-loop smart-grid testbed that were planned by large language models (LLMs) and executed through an attack toolkit (Kellerer and Hagenmeyer, 2026a, 2026b).
2. **AI-generated training data.** Kampourakis et al. (2026) use LLMs to synthesise labelled network-traffic records for IDS research.

The project studies the first meaning. The second is reviewed because it was an optional data source in Phase 1.

## 2.5 Evaluation practice

Arp et al. (2022) list pitfalls that make security ML results look better than they are. Three of them matter for CICIoT2023: **data snooping** (information from the test set reaching training), **spurious correlations** (features that encode how the data were collected rather than the attack), and **inappropriate performance measures** (for example accuracy on imbalanced data). The project's data audit found all three risks in the local CICIoT2023 release: 55.0 % exact duplicate rows, 30.6 % of rows sharing their feature vector with another class, window-size features that encode the extraction setting, and time-ordered rows.

# 3. Review of the core papers

## 3.1 Neto et al. (2023) - CICIoT2023 dataset and benchmark

* **What it is.** A dataset of 33 attacks in 7 families (DDoS, DoS, Recon, Web-based, Brute force, Spoofing, Mirai) run against a topology of 105 real IoT devices. Features are computed over windows of packets.
* **Benchmark protocol.** Benign and malicious data are combined and shuffled, then split at random into 80 % train and 20 % test, and standardised. Five models are compared: Logistic Regression, Perceptron, AdaBoost, Random Forest (RF) and a deep neural network (DNN).
* **Results (their Table 6).** Accuracy is above 98 % for every model, but the F1-score separates them:

| Task | RF accuracy | RF F1 | DNN accuracy | DNN F1 |
|---|---|---|---|---|
| 34 classes | 0.992 | 0.714 | 0.986 | 0.672 |
| 8 classes | 0.994 | 0.719 | 0.991 | 0.697 |
| 2 classes | 0.997 | 0.965 | 0.994 | 0.940 |

* **What matters for this project.** The dataset's own authors report a **multi-class F1 of about 0.70**, not 0.99. The very high accuracy comes from the dominant DDoS and DoS classes. Their confusion matrices (Tables 7-8) show the remaining errors among Benign, Recon, Spoofing, Web and Brute force.
* **Limitations.** A random split of time-ordered, heavily duplicated data lets near-copies of the same window appear in both train and test. No federated, poisoning or evasion experiments. No AI-coordinated attack category.

## 3.2 Bilal et al. (2026) - dataset-centric evaluation of federated IDS

* **Question.** How well do federated IDS models generalise across IoT datasets?
* **Data.** Edge-IIoTset, CIC-IoT2023 and TII-SSRC-23. Labels are harmonised to families, and features are aligned to a 40-feature intersection.
* **Federation.** CIC-IoT2023 is split into 10 clients by device group ("moderate non-IID"), with 5 local epochs, 50 rounds and full participation. FedAvg, FedProx (μ = 10^-3^) and FedNova are compared, with an LSTM and a Transformer backbone.
* **Results.**
  * CIC-IoT2023, 8 classes (their Table 6): F1 92.0 (FedAvg-LSTM) to 95.2 (FedNova-Transformer); accuracy 95-97 %.
  * FedProx and FedNova gain 1-2 points over FedAvg.
  * FL is reported to be close to centralised training.
  * Cross-dataset transfer loses up to 30 points of macro-F1, and training on all three datasets restores about 90 %.
* **Strengths.** Three datasets, a cross-dataset protocol and communication accounting (rounds to 95 % accuracy, MB exchanged).
* **Limitations relevant here.**
  * Single runs, with no seeds or confidence intervals.
  * The test splits were "roughly balanced" between benign and attack.
  * Duplicate removal and the split unit (random rows or files) are not described.
  * No poisoning, no evasion, and no fixed false-positive operating point.

## 3.3 Nayak and Reddy (2026) - Byzantine-resilient federated edge IDS

* **Question.** Which aggregation rule keeps a federated IoT IDS accurate under non-IID data and a bounded fraction of malicious clients, with a model small enough for edge hardware?
* **Setup.**
  * Data: CICIoT2023 (primary), TON_IoT and Edge-IIoTset, each reduced to a balanced **binary** task (200,000 rows for CICIoT2023) with the 40 features of highest mutual information.
  * Federation: 20 clients, Dirichlet α = 0.3, 40 rounds.
  * Model: a CNN-BiLSTM of about 6,300 parameters.
  * Aggregators: FedAvg, coordinate-wise median, trimmed mean (β = 0.35), multi-Krum and FLTrust.
  * Attacks: sign-flipping, label-flipping and model replacement.
  * Protocol: 641 runs, 5 seeds for headline results, 95 % confidence intervals, Holm-corrected paired t-tests, MCC as the primary metric.
* **Results.**
  * CICIoT2023 clean F1 is 0.989-0.990 for every rule.
  * With 30 % sign-flipping clients, FedAvg collapses to a constant prediction (MCC 0.979 → 0.000), the median falls to F1 0.661 and the trimmed mean to 0.693. Multi-Krum and FLTrust hold 0.990.
  * Breakdown points under sign-flipping: FedAvg at 5 %, median and trimmed mean at 20 %, multi-Krum at 45 %, and FLTrust above 45 %.
  * On TON_IoT and Edge-IIoTset the best clean configuration is plain FedAvg, so robustness has a clean-data cost.
  * Client-level differential privacy destroyed detection at every budget tested.
  * One inference takes 23.5 ms on an ESP32.
* **Strengths.** The most rigorous protocol among the reviewed papers. The authors also report correcting their own sampling error: a prefix sample had been 91.4 % attack and had given misleading perfect scores.
* **Limitations (stated by the authors).**
  * Binary task only.
  * A random rather than temporal split.
  * A simulated federation with full participation.
  * Non-adaptive attackers.
  * No evasion study.

## 3.4 Kampourakis et al. (2026) - Knowledge-to-Data

* **Question.** Can LLMs generate structured network-traffic data that is good enough for IDS research without a testbed?
* **Method.** Protocol documentation, attack semantics and explicit statistical rules are written into prompts. Four LLMs (ChatGPT-5, Gemini 2.5 Pro, Claude Opus 4.1, Qwen3-Max) generate records in a 16-feature AWID3 (IEEE 802.11) schema.
* **Results.**
  * Synthetic data reach a mean cosine similarity of up to 0.979 with real data.
  * Gradient-boosting classifiers trained only on synthetic data and tested on real AWID3 reach F1 up to 0.956.
  * Signal-layer noise is reproduced less well.
* **Relevance and limits.**
  * The work is about AI-*generated data*, not attacks executed by AI.
  * It uses Wi-Fi rather than IP-flow features, so it does not apply directly to CICIoT2023 or GridStratLLM.
  * It was listed as optional in Phase 1 and was not used.

## 3.5 Kellerer and Hagenmeyer (2026a, 2026b) - GridStratLLM

* **What it is.** LLM agents planned coordinated attacks on a hardware-in-the-loop smart-grid testbed (S7 and Modbus control traffic). The attacks were executed through an attack toolkit that includes ARP man-in-the-middle and data modification.
* **What is released.** PCAPs, packet metadata, SCADA process data, LLM session records and execution steps: 6.5 GB under CC BY 4.0.
* **Relevance.** It is the only identified public dataset of real attacks planned by LLMs. It is smart-grid/SCADA data, not generic IoT, so it must be analysed on its own.

# 4. Comparison

## 4.1 Scope comparison

| | Neto et al. 2023 | Bilal et al. 2026 | Nayak & Reddy 2026 | Kampourakis et al. 2026 | **This project** |
|---|---|---|---|---|---|
| Main dataset(s) | CICIoT2023 | Edge-IIoTset, CIC-IoT2023, TII-SSRC-23 | CICIoT2023, TON_IoT, Edge-IIoTset | AWID3 (synthetic vs real) | CICIoT2023, GridStratLLM |
| Tasks | 2, 8, 34 classes | Family-level multi-class | Binary | Multi-class (AWID3) | 2, 8, 34 classes; binary per LLM session |
| Split | Random 80/20 | Not fully stated; balanced test | Random, balanced sample | Train synthetic / test real | File-level and purged time blocks, de-duplicated |
| Federated | No | FedAvg, FedProx, FedNova | FedAvg + 4 robust rules | No | FedAvg, FedProx; simulator + Flower across Azure and a laptop |
| Non-IID | - | Device groups | Dirichlet α = 0.3 | - | IID, Dirichlet α = 1.0 and α = 0.1 |
| Poisoning | No | No | Sign-flip, label-flip, model replacement; 5-45 % sweep | No | Sign-flip, targeted DDoS→Benign + boosting; 10-30 % sweep |
| Robust aggregation | - | - | Median, trimmed mean, multi-Krum, FLTrust | - | Median, trimmed mean, norm clipping |
| Inference-time evasion | No | No | No | No | Label-only black-box, realisable constraints, + adversarial training |
| AI-coordinated attacks | No | No | No | LLM-*generated* data | LLM-*planned* attacks, leave-one-LLM-out |
| Fixed false-positive rate | No | No | FPR reported | No | Thresholds for 5 % and 1 % benign FPR, fitted on validation |
| Seeds / uncertainty | Single run | Single run | 3-5 seeds, 95 % CI, Holm tests | Single run per LLM | 3 seeds for main cells (± sd); 1 seed for sweeps |
| Real deployment | Testbed capture | Simulated | Simulated; ESP32 inference | - | Flower across 2 Azure VMs + laptop over TLS; Azure HTTPS endpoint |

## 4.2 Detection results on CICIoT2023

Higher numbers in a paper do not mean a better detector when the protocols differ. The table puts the reported figures side by side with each paper's protocol.

| Study | Task | Protocol | Model | Reported F1 |
|---|---|---|---|---|
| Neto et al. 2023 | 8 classes | Random 80/20, all rows | RF / DNN | 0.719 / 0.697 |
| Neto et al. 2023 | 34 classes | Random 80/20, all rows | RF / DNN | 0.714 / 0.672 |
| Neto et al. 2023 | binary | Random 80/20, all rows | RF / DNN | 0.965 / 0.940 |
| Bilal et al. 2026 | 8 classes | 10 device-group clients, balanced test | FedAvg-LSTM / FedNova-Transformer | 0.920 / 0.952 |
| Nayak & Reddy 2026 | binary | Balanced 200 k sample, 20 clients α = 0.3 | Any rule, no attack | 0.989-0.990 |
| **This project** | 8 classes | File/time split, de-duplicated, 33 window-invariant features | MLP (3 seeds) / RF | **0.687 ± 0.005 / 0.709** |
| **This project** | 34 classes | same | MLP v2 (3 seeds) / RF | **0.574 / 0.591** |
| **This project** | binary | same | MLP (3 seeds) / RF | **0.750 ± 0.004 / 0.747** |
| **This project** | binary | same, whole test pool at natural prior (8.98 M windows) | MLP, seed 0 | **0.920** |
| **This project** | 8 classes | same, federated | FedAvg IID / FedAvg α = 0.1 | **0.668 / 0.423** |

**Reading the table.**

* **Multi-class results agree with the dataset authors.** The project's 8-class macro-F1 (MLP 0.687, RF 0.709) is within 0.01-0.03 of Neto et al.'s own RF and DNN results (0.719 / 0.697), even though the split here is stricter. The errors also fall in the same place. Neto et al. write that Web and Brute force are "usually classified as benign, Recon, or spoofing" and that performance degrades for Benign, Recon and Spoofing. The project finds the same: Web and Brute force are the weakest classes, and Benign windows are flagged mostly as Recon, Spoofing or Web.
* **The 0.92-0.99 results come from easier protocols.** Bilal et al. use a balanced test set, and Nayak and Reddy a balanced binary sample with a random split. Both remove the class imbalance that makes the benign class hard. Their split files are not available, so the size of each effect cannot be separated, but the direction is consistent with what the project's audit found about duplicates and shortcut features.
* **Binary results depend on the class prior.** On the de-duplicated, capped test split the binary MLP reaches 0.750. On the whole test pool at the natural prior, where attack windows dominate, it reaches 0.920, close to Neto et al.'s 0.940 (DNN).
* **Accuracy, side by side.** Neto et al. report 99.4 % (8-class RF) and 99.7 % (binary RF). The project's RF reaches 82.8 % (8-class) and 96.9 % (binary) on the de-duplicated test split, and 78.6 % / 98.0 % on the whole test pool. Most of the 8-class errors are DDoS and DoS windows confused with each other (18-22 % for the MLP). Most of the 30.6 % of raw rows that share their feature vector with another class are DDoS-X/DoS-X pairs, and these two families are the largest in the dataset, so they dominate accuracy.
* **Accuracy hides the benign class.** Every paper reports accuracy of 95-99 %. In the project, the same models flag 19-29 % of benign windows at argmax. This is why the project reports detection at a fixed benign false-positive rate instead: at 1 % FPR the v2 MLP detects 83-85 % of attack windows, and HistGradientBoosting 85-86 %.

## 4.3 Federated learning results

| Finding | Bilal et al. 2026 | Nayak & Reddy 2026 | This project | Agreement |
|---|---|---|---|---|
| FL vs centralised, mild heterogeneity | "Minimal loss in accuracy" | Not compared | -0.02 macro-F1 (8-class, IID); 0.6-2.5 points of detection at 1 % FPR | Agrees |
| FedProx vs FedAvg | +0.7 to +1.0 F1 points (CIC-IoT2023) | Not compared | -0.2 to +0.05 macro-F1; within one sd | Agrees: small or no gain |
| Strong label skew | Not tested (device groups, "moderate") | α = 0.3: clean F1 0.99 on balanced binary | α = 0.1: 8-class macro-F1 0.42 ± 0.11; benign FPR 0.60; not fixed by 60 rounds or FedProx | New result |
| Communication | FedNova needs 20 % fewer rounds (combined data) | - | 30 MB per 30-round run (v1); 50 % participation halves it at ≤ 0.4 points cost | Complementary |
| Real deployment | Simulated | Simulated | Flower across Azure + laptop reproduces the simulator to 4 decimals (0.6692) | New result |

## 4.4 Poisoning and robust aggregation

| Finding | Nayak & Reddy 2026 (CICIoT2023, binary, 20 clients, α = 0.3) | This project (CICIoT2023, 10 clients) |
|---|---|---|
| FedAvg under sign-flip | Collapses at 30 % (MCC 0); breaks at 5 % | Collapses at 20 % (macro-F1 0.008 8-class, 0.038 binary); loses 0.02-0.03 at 10 % |
| Coordinate-wise median | Falls to F1 0.661 at 30 %; breakdown at 20 % | Holds at 30 % with IID clients (8-class 0.665 vs 0.668 clean); partial with α = 1.0 (benign FPR 0.31 → 0.42-0.50) |
| Trimmed mean | β = 0.35: F1 0.693 at 30 %; breakdown at 20 % | β = 0.2: holds at 20 %, fails at 30 % (8-class 0.477, benign FPR 0.77) |
| Targeted attack | Label-flip; model replacement | DDoS→Benign + boosting: FedAvg hides 23-62 % of DDoS windows (IID); robust rules keep it ≤ 0.3 % |
| Clean-data cost of robustness | Large on TON_IoT / Edge-IIoTset | ≤ 0.001 macro-F1 (IID); binary median 0.733 vs 0.757 (α = 1.0) |

**Interpretation.** The two studies agree on the main points:

1. Plain FedAvg is defeated by a small fraction of malicious clients.
2. Coordinate-wise rules hold only within their assumptions.
3. Non-IID data weakens them and adds a clean-data cost.

The difference in the median's behaviour at 30 % is consistent with the difference in client heterogeneity: IID here, α = 0.3 there. The project's own α = 1.0 runs already show partial failure. The project did not test multi-Krum or FLTrust, which Nayak and Reddy found to be the strongest rules.

## 4.5 Evasion and AI-coordinated attacks

None of the reviewed papers evaluates inference-time evasion against a CICIoT2023 detector, or detection of LLM-planned attacks. The project's results here have no direct published comparison point:

* **Evasion.** A label-only attacker that can only pad, slow down and re-TTL its own packets turns 24-49 % of detected windows benign at the deployable 1 %-FPR threshold. This is more than at argmax. Two rounds of adversarial training reduce it to 8-17 % at negligible clean cost.
* **LLM-planned attacks.** Network signatures of LLM-planned attacks transfer across planning LLMs (leave-one-LLM-out AUC 0.90-1.00) because every session uses the same toolkit. The detection survives removal of the ARP signature, which the project tested and which was an open question after the Phase 1 analysis.

# 5. Gap analysis

| Gap in the reviewed work | Evidence | How the project addresses it |
|---|---|---|
| **G1. Optimistic evaluation protocols on CICIoT2023** | Random or balanced splits; no de-duplication reported; accuracy as headline | Provenance and leakage audit; file/time-aware split with de-duplication; macro-F1, balanced accuracy and detection at fixed benign FPR; "unseen" test subset |
| **G2. Poisoning and evasion are studied separately, or evasion not at all** | Nayak & Reddy cover poisoning only; Bilal et al. neither | One detector pipeline evaluated under both threats, each with its own threat model |
| **G3. No operating-point analysis** | No study fixes the benign false-positive rate | Thresholds for 5 % and 1 % FPR fitted on validation; shows that the deployable threshold is the most evadable one |
| **G4. Strong label skew not tested on CICIoT2023 multi-class** | Bilal et al.: moderate device-group skew; Nayak & Reddy: binary α = 0.3 | α = 0.1 for 3 tasks, 3 seeds, 60-round check: a failure that FedProx does not fix |
| **G5. Simulation only** | All reviewed FL studies are simulated | Flower deployment across two Azure VMs and a laptop over TLS, matching the simulator |
| **G6. No evaluation of detecting LLM-planned attacks** | Kampourakis et al. study LLM-generated data, not attacks | Leave-one-LLM-out on GridStratLLM, plus a test without the ARP signature |

**What the project does not claim.** No new algorithm, no formal privacy (Nayak and Reddy show that client-level DP is hard at this scale), and no cross-dataset transfer (Bilal et al.'s main topic). The contribution is an **evaluation**: stricter data handling, an operating-point view, and both attack types plus LLM-planned attacks in one reproducible pipeline.

# 6. Lessons taken from the literature into the project

* From **Neto et al.**: three label granularities (2, 8 and 34 classes) and the RF baseline, so that the results stay comparable with the dataset's own benchmark.
* From **Nayak and Reddy**: multi-seed reporting and an adversarial-fraction sweep. The project has 3 seeds for its main cells, but its sweep and non-IID poisoning cells have only 1 seed, which is a stated limitation.
* From **Bilal et al.**: communication accounting and rounds to a target score, which the project reports as rounds to 95 % of centralised macro-F1.
* From **Arp et al.** and **Apruzzese et al.**: the data audit and the realisable evasion constraints.

# References

* Apruzzese, G., Andreolini, M., Ferretti, L., Marchetti, M., & Colajanni, M. (2022). Modeling realistic adversarial attacks against network intrusion detection systems. *Digital Threats: Research and Practice*, 3(3), Article 31. https://doi.org/10.1145/3469659
* Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine learning in computer security. In *31st USENIX Security Symposium* (pp. 3971-3988).
* Bagdasaryan, E., Veit, A., Hua, Y., Estrin, D., & Shmatikov, V. (2020). How to backdoor federated learning. In *Proceedings of the 23rd International Conference on Artificial Intelligence and Statistics (AISTATS)*, PMLR 108, 2938-2948.
* Bilal, M. A., Ul Islam, I., Idrees, S., Qasim, M., Khan, M. J., & Khan, J. (2026). Dataset-centric evaluation of federated intrusion detection models in IoT networks. *Scientific Reports*, 16, Article 2683. https://doi.org/10.1038/s41598-025-32567-w
* Hsu, T.-M. H., Qi, H., & Brown, M. (2019). Measuring the effects of non-identical data distribution for federated visual classification. arXiv:1909.06335.
* Kampourakis, K. E., Kampourakis, V., Chatzoglou, E., Kambourakis, G., & Gritzalis, S. (2026). Knowledge-to-Data: LLM-driven synthesis of structured network traffic for testbed-free IDS evaluation. arXiv:2601.05022. https://arxiv.org/abs/2601.05022
* Kellerer, N., & Hagenmeyer, V. (2026a). GridStratLLM: Agent framework for coordinated cyberattacks on the smart grid with large language models [Dataset]. Karlsruhe Institute of Technology. https://doi.org/10.35097/bx5337kcykte438h
* Kellerer, N., & Hagenmeyer, V. (2026b). GridStratLLM: Agent framework for coordinated cyberattacks on the smart grid with large language models. In *Proceedings of the 2026 ACM Sustainability Week* (pp. 110-123). ACM. https://doi.org/10.1145/3765611.3815147
* Li, T., Sahu, A. K., Zaheer, M., Sanjabi, M., Talwalkar, A., & Smith, V. (2020). Federated optimization in heterogeneous networks. *Proceedings of Machine Learning and Systems*, 2, 429-450.
* McMahan, B., Moore, E., Ramage, D., Hampson, S., & Agüera y Arcas, B. (2017). Communication-efficient learning of deep networks from decentralized data. In *Proceedings of the 20th International Conference on Artificial Intelligence and Statistics (AISTATS)*, PMLR 54, 1273-1282.
* Nayak, R., & Reddy, G. N. (2026). Byzantine-resilient federated edge intrusion detection for heterogeneous IoT networks under non-IID conditions. *Discover Artificial Intelligence*, 6, Article 1409. https://doi.org/10.1007/s44163-026-02405-7
* Neto, E. C. P., Dadkhah, S., Ferreira, R., Zohourian, A., Lu, R., & Ghorbani, A. A. (2023). CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment. *Sensors*, 23(13), 5941. https://doi.org/10.3390/s23135941
* Pierazzi, F., Pendlebury, F., Cortellazzi, J., & Cavallaro, L. (2020). Intriguing properties of adversarial ML attacks in the problem space. In *2020 IEEE Symposium on Security and Privacy* (pp. 1332-1349).
* Sun, Z., Kairouz, P., Suresh, A. T., & McMahan, H. B. (2019). Can you really backdoor federated learning? arXiv:1911.07963.
* Yin, D., Chen, Y., Ramchandran, K., & Bartlett, P. (2018). Byzantine-robust distributed learning: Towards optimal statistical rates. In *Proceedings of the 35th International Conference on Machine Learning*, PMLR 80, 5650-5659.

*Secondary sources, cited as described by Nayak and Reddy (2026) and Bilal et al. (2026), not checked separately:* Blanchard et al. (2017), Krum and multi-Krum; Cao et al. (2021), FLTrust; Wang et al. (2020), FedNova; Ferrag et al. (2022), Edge-IIoTset.
