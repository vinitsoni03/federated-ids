| task | setting | model | split | n_seeds | macro_f1 | macro_f1_sd | macro_f1_per_seed | weighted_f1 | balanced_accuracy | benign_fpr | attack_detection_rate | macro_pr_auc | train_seconds |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| category | 8-class, 33 features | mlp | test | 3 | 0.6870 | 0.0048 | 0.6897 / 0.6897 / 0.6814 | 0.8144 | 0.7104 | 0.2641 | 0.9672 | 0.7288 | 76.3000 |
| category | 8-class, 33 features | mlp | test_unseen | 3 | 0.6914 | 0.0050 | 0.6941 / 0.6945 / 0.6856 | 0.8188 | 0.7155 | 0.2636 | 0.9625 | 0.7327 | 76.3000 |
| category | 8-class, 33 features | mlp | test_full_pool | 1 | 0.6058 | 0.0000 | 0.6058 | 0.7908 | 0.6990 | 0.2962 | 0.9980 |  | 92.9000 |
| category | 8-class, 33 features | random_forest | test | 1 | 0.7090 | 0.0000 | 0.7090 | 0.8231 | 0.6798 | 0.4638 | 0.9872 | 0.7353 | 33.4000 |
| category | 8-class, 33 features | random_forest | test_unseen | 1 | 0.7153 | 0.0000 | 0.7153 | 0.8317 | 0.6853 | 0.4637 | 0.9855 | 0.7421 | 33.4000 |
| category | 8-class, 33 features | random_forest | test_full_pool | 1 | 0.6067 | 0.0000 | 0.6067 | 0.7913 | 0.6594 | 0.4708 | 0.9991 |  | 33.4000 |
| class34 | 34-class, 33 features | mlp | test | 3 | 0.5558 | 0.0265 | 0.5694 / 0.5253 / 0.5728 | 0.6747 | 0.5709 | 0.2618 | 0.9622 | 0.5944 | 73.8667 |
| class34 | 34-class, 33 features | mlp | test_unseen | 3 | 0.5577 | 0.0270 | 0.5710 / 0.5266 / 0.5754 | 0.6793 | 0.5714 | 0.2608 | 0.9567 | 0.5949 | 73.8667 |
| class34 | 34-class, 33 features | mlp | test_full_pool | 1 | 0.5351 | 0.0000 | 0.5351 | 0.7232 | 0.5859 | 0.2401 | 0.9975 |  | 100.9000 |
| class34 | 34-class, 33 features | random_forest | test | 1 | 0.5914 | 0.0000 | 0.5914 | 0.7172 | 0.5941 | 0.2850 | 0.9696 | 0.6074 | 49.7000 |
| class34 | 34-class, 33 features | random_forest | test_unseen | 1 | 0.5928 | 0.0000 | 0.5928 | 0.7228 | 0.5951 | 0.2844 | 0.9653 | 0.6104 | 49.7000 |
| class34 | 34-class, 33 features | random_forest | test_full_pool | 1 | 0.5409 | 0.0000 | 0.5409 | 0.7171 | 0.5896 | 0.2957 | 0.9980 |  | 49.7000 |
| binary | binary, 33 features | mlp | test | 3 | 0.7500 | 0.0038 | 0.7498 / 0.7463 / 0.7539 | 0.9525 | 0.8785 | 0.1919 | 0.9490 | 0.7770 | 34.6667 |
| binary | binary, 33 features | mlp | test_unseen | 3 | 0.7478 | 0.0039 | 0.7476 / 0.7440 / 0.7517 | 0.9459 | 0.8753 | 0.1911 | 0.9416 | 0.7769 | 34.6667 |
| binary | binary, 33 features | mlp | test_full_pool | 1 | 0.9202 | 0.0000 | 0.9202 | 0.9900 | 0.9045 | 0.1872 | 0.9962 |  | 27.2000 |
| binary | binary, 33 features | random_forest | test | 1 | 0.7467 | 0.0000 | 0.7467 | 0.9650 | 0.7027 | 0.5859 | 0.9913 | 0.7945 | 26.5000 |
| binary | binary, 33 features | random_forest | test_unseen | 1 | 0.7459 | 0.0000 | 0.7459 | 0.9604 | 0.7021 | 0.5860 | 0.9902 | 0.7951 | 26.5000 |
| binary | binary, 33 features | random_forest | test_full_pool | 1 | 0.7849 | 0.0000 | 0.7849 | 0.9764 | 0.7075 | 0.5844 | 0.9994 |  | 26.5000 |
| category | 8-class, all 39 features (shortcut ablation) | mlp | test | 1 | 0.6959 | 0.0000 | 0.6959 | 0.8209 | 0.7079 | 0.2823 | 0.9704 | 0.7320 | 55.5000 |
| category | 8-class, all 39 features (shortcut ablation) | mlp | test_unseen | 1 | 0.7002 | 0.0000 | 0.7002 | 0.8254 | 0.7130 | 0.2818 | 0.9662 | 0.7358 | 55.5000 |
| category | 8-class, all 39 features (shortcut ablation) | mlp | test_full_pool | 1 | 0.6237 | 0.0000 | 0.6237 | 0.8101 | 0.6968 | 0.2875 | 0.9980 |  | 55.5000 |
| category | 8-class, all 39 features (shortcut ablation) | random_forest | test | 1 | 0.7124 | 0.0000 | 0.7124 | 0.8247 | 0.6839 | 0.4634 | 0.9868 | 0.7416 | 32.2000 |
| category | 8-class, all 39 features (shortcut ablation) | random_forest | test_unseen | 1 | 0.7188 | 0.0000 | 0.7188 | 0.8335 | 0.6895 | 0.4633 | 0.9851 | 0.7486 | 32.2000 |
| category | 8-class, all 39 features (shortcut ablation) | random_forest | test_full_pool | 1 | 0.6086 | 0.0000 | 0.6086 | 0.7913 | 0.6631 | 0.4685 | 0.9991 |  | 32.2000 |
