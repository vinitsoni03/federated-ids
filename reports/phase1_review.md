# Milestone 1 - review of the Phase-1 documents (2026-10-26)

Reviewed: `Downloads/Phase1_Final_Verified/01_Problem_Definition.docx`, `02_Literature_Survey.docx`,
`03_Proposed_Architecture_and_Methodology.docx`, `04_Form_Text.txt`, `05_Verification_Report.txt`
(text extracted from the DOCX XML). The documents were **not** rewritten. One internal error was
corrected in a copy; the other findings are listed with proposed text for the student to accept or reject.

## What is sound (kept)
* Title, problem area and the separation of threat models are consistent across all documents.
* Dataset claims are cautious and match what was later verified locally: CICIoT2023 has no
  AI-generated-attack category; GridStratLLM is smart-grid/SCADA data with 6.5 GB, CC BY 4.0,
  normal + five LLM attack datasets (all confirmed from the bag, `reports/dataset_audit.md` §3).
* No results, novelty, DP or secure-aggregation claims are made. FL privacy is described correctly.
* References are formatted consistently (APA-like) and placed in a References section.

## Problems found

| # | Document | Problem | Action |
|---|---|---|---|
| 1 | 03 Methodology §1 | Workflow labels evasion "Experiment A" and FL "Experiment B", but §3-§5 define A = AI-coordinated detection, B = evasion, C = poisoning. | **Fixed in a copy**: `Downloads/Phase1_Rev2_20261026/03_Proposed_Architecture_and_Methodology.docx` (workflow now says B = evasion, C = federated). Original untouched. |
| 2 | 01 §4, §6 | No research question or objective on the *federated baseline itself* (centralized vs FedAvg vs FedProx under IID/non-IID), although the title is about federated IDS and the methodology needs it before poisoning. | Proposed RQ (insert after RQ1): "How do FedAvg and FedProx compare with centralized training on CICIoT2023 under IID and Dirichlet label-skewed clients, in macro-F1, benign false-positive rate, convergence and communication?" |
| 3 | 01 §3 vs 03 §5 vs implementation | Poisoning defence: "one justified robust aggregator" in Phase 1; the implementation compares three (median, trimmed mean, norm clipping) and two attacks (untargeted sign-flip, targeted label-flip with boosting). | Update wording to "robust aggregators (coordinate-wise median, trimmed mean, norm clipping)" in Phase 2; scope grew, the approach did not change. |
| 4 | 01 §4 RQ3 / 03 §4 | "Minority-class recall" under evasion: the evasion goal actually defined (`reports/threat_models.md`) is attack -> Benign; per-class evasion rate is the right metric. | Proposed RQ3: "Under a black-box, label-only attacker who can only pad packets, slow down and set TTL on its own traffic, what fraction of detected attack windows can be made to look Benign, and at what throughput cost?" |
| 5 | 01, 03 | Dataset facts discovered in the audit are not in Phase 1 and change the methodology: no label column, 55 % exact duplicates, 30.6 % of rows share their feature vector with another class, the window-size shortcut (`Number`), time-ordered rows. | Add a short "Data-quality findings" paragraph in Phase 2 citing `reports/dataset_audit.md`. |
| 6 | 02 Literature survey | Only six sources; none of the foundational methods actually used are cited (FedAvg, FedProx, Dirichlet non-IID protocol, median/trimmed mean, boosting attack, problem-space evasion, ML-security pitfalls). | Add the references below. |
| 7 | 01 §8 / 03 §3 | GridStratLLM: Phase 1 plans "labels from documented session/execution metadata". Confirmed feasible; but packet-level labels are incomplete and the commercial-NSM clock is not alignable (`reports/dataset_audit.md` §3.3). | State both limitations in Phase 2. |
| 8 | Title | "AI-Enabled Cyberattack Detection" can be read as AI-enabled *detection* or detection of AI-enabled *attacks*. The project does both. | Optional; no change made. |

## References to add (verification status stated honestly)
Verified online on 2026-10-26 (publisher / proceedings / DBLP record found):
* Apruzzese, G., Andreolini, M., Ferretti, L., Marchetti, M., & Colajanni, M. (2022). Modeling realistic adversarial attacks against network intrusion detection systems. *Digital Threats: Research and Practice*, 3(3), Article 31. https://doi.org/10.1145/3469659
* Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine learning in computer security. In *31st USENIX Security Symposium* (pp. 3971-3988).
* Li, T., Sahu, A. K., Zaheer, M., Sanjabi, M., Talwalkar, A., & Smith, V. (2020). Federated optimization in heterogeneous networks. *Proceedings of Machine Learning and Systems*, 2, 429-450.
* Yin, D., Chen, Y., Kannan, R., & Bartlett, P. (2018). Byzantine-robust distributed learning: Towards optimal statistical rates. In *Proceedings of the 35th ICML*, PMLR 80, 5650-5659.

Standard references, details from memory - **check against the publisher before submission**:
* McMahan, B., Moore, E., Ramage, D., Hampson, S., & Agüera y Arcas, B. (2017). Communication-efficient learning of deep networks from decentralized data. *AISTATS*, PMLR 54, 1273-1282.
* Hsu, T.-M. H., Qi, H., & Brown, M. (2019). Measuring the effects of non-identical data distribution for federated visual classification. arXiv:1909.06335.
* Bagdasaryan, E., Veit, A., Hua, Y., Estrin, D., & Shmatikov, V. (2020). How to backdoor federated learning. *AISTATS*, PMLR 108, 2938-2948.
* Sun, Z., Kairouz, P., Suresh, A. T., & McMahan, H. B. (2019). Can you really backdoor federated learning? arXiv:1911.07963.
* Pierazzi, F., Pendlebury, F., Cortellazzi, J., & Cavallaro, L. (2020). Intriguing properties of adversarial ML attacks in the problem space. *IEEE S&P*, 1332-1349.

## Novelty boundary (unchanged, now with evidence)
Federated IDS on CICIoT2023, non-IID FL and Byzantine-robust aggregation are established areas
(Bilal et al., 2026; Nayak & Reddy, 2026; Yin et al., 2018). What this project can defensibly claim
is an **evidence-backed evaluation**: a provenance/leakage audit that exposes duplicate, cross-label
and window-size artifacts in the local CICIoT2023 release; leakage-aware splits; separate,
explicitly-threat-modelled poisoning and evasion experiments; and a leave-one-LLM-out analysis of
GridStratLLM. No claim of a new algorithm is made. The full texts of Bilal et al. and Nayak & Reddy
were not read in this session; any comparison with their numbers must wait until they are.
