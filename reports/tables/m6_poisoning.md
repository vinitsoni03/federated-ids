| task | partition | attack | aggregator | n_seeds | macro_f1 | macro_f1_sd | benign_fpr | attack_detection_rate | ddos_pred_benign | wall_clock_s |
|---|---|---|---|---|---|---|---|---|---|---|
| category | iid | No attack | FedAvg | 3 | 0.6685 | 0.0008 | 0.2822 | 0.9644 | 0.0019 | 92.7000 |
| category | iid | No attack | Median | 3 | 0.6681 | 0.0007 | 0.2788 | 0.9640 | 0.0019 | 92.5000 |
| category | iid | No attack | Trimmed mean | 3 | 0.6684 | 0.0003 | 0.2800 | 0.9640 | 0.0019 | 92.5333 |
| category | iid | No attack | Norm clip | 3 | 0.6686 | 0.0010 | 0.2814 | 0.9643 | 0.0019 | 92.8000 |
| category | iid | Sign-flip x5 (20 %) | FedAvg | 3 | 0.0079 | 0.0027 | 0.3293 | 0.1512 | 0.8724 | 92.8333 |
| category | iid | Sign-flip x5 (20 %) | Median | 3 | 0.6657 | 0.0028 | 0.2963 | 0.9652 | 0.0020 | 92.5667 |
| category | iid | Sign-flip x5 (20 %) | Trimmed mean | 3 | 0.6661 | 0.0028 | 0.3016 | 0.9658 | 0.0020 | 92.9000 |
| category | iid | Sign-flip x5 (20 %) | Norm clip | 3 | 0.6607 | 0.0020 | 0.3164 | 0.9666 | 0.0022 | 92.7333 |
| category | iid | DDoS->Benign boost (20 %) | FedAvg | 3 | 0.5015 | 0.0049 | 0.5210 | 0.6964 | 0.6187 | 92.8667 |
| category | iid | DDoS->Benign boost (20 %) | Median | 3 | 0.6674 | 0.0011 | 0.2860 | 0.9644 | 0.0022 | 93.1000 |
| category | iid | DDoS->Benign boost (20 %) | Trimmed mean | 3 | 0.6661 | 0.0015 | 0.2889 | 0.9644 | 0.0023 | 92.6000 |
| category | iid | DDoS->Benign boost (20 %) | Norm clip | 3 | 0.6624 | 0.0035 | 0.3099 | 0.9661 | 0.0025 | 92.8667 |
| category | dir1.0 | No attack | FedAvg | 1 | 0.6683 | 0.0000 | 0.3279 | 0.9694 | 0.0017 | 92.1000 |
| category | dir1.0 | No attack | Median | 1 | 0.6647 | 0.0000 | 0.3140 | 0.9679 | 0.0020 | 91.2000 |
| category | dir1.0 | No attack | Trimmed mean | 1 | 0.6646 | 0.0000 | 0.3107 | 0.9675 | 0.0019 | 92.0000 |
| category | dir1.0 | No attack | Norm clip | 1 | 0.6665 | 0.0000 | 0.3309 | 0.9692 | 0.0018 | 91.1000 |
| category | dir1.0 | Sign-flip x5 (20 %) | FedAvg | 1 | 0.4660 | 0.0000 | 1.0000 | 1.0000 | 0.0000 | 91.8000 |
| category | dir1.0 | Sign-flip x5 (20 %) | Median | 1 | 0.6462 | 0.0000 | 0.4679 | 0.9803 | 0.0012 | 91.6000 |
| category | dir1.0 | Sign-flip x5 (20 %) | Trimmed mean | 1 | 0.6404 | 0.0000 | 0.5040 | 0.9826 | 0.0011 | 93.5000 |
| category | dir1.0 | Sign-flip x5 (20 %) | Norm clip | 1 | 0.6498 | 0.0000 | 0.4212 | 0.9766 | 0.0013 | 91.5000 |
| category | dir1.0 | DDoS->Benign boost (20 %) | FedAvg | 1 | 0.6479 | 0.0000 | 0.3740 | 0.9676 | 0.0161 | 91.1000 |
| category | dir1.0 | DDoS->Benign boost (20 %) | Median | 1 | 0.6620 | 0.0000 | 0.3490 | 0.9712 | 0.0019 | 91.7000 |
| category | dir1.0 | DDoS->Benign boost (20 %) | Trimmed mean | 1 | 0.6578 | 0.0000 | 0.3463 | 0.9709 | 0.0021 | 91.4000 |
| category | dir1.0 | DDoS->Benign boost (20 %) | Norm clip | 1 | 0.6635 | 0.0000 | 0.3588 | 0.9721 | 0.0017 | 91.0000 |
| category | iid | signflip (10%) | fedavg | 1 | 0.6400 |  | 0.3989 | 0.9720 | 0.0025 | 92.1000 |
| category | iid | signflip (10%) | trimmed_mean | 1 | 0.6700 |  | 0.3046 | 0.9670 | 0.0020 | 92.0000 |
| category | iid | signflip (10%) | median | 1 | 0.6698 |  | 0.3033 | 0.9669 | 0.0020 | 93.3000 |
| category | iid | signflip (30%) | fedavg | 1 | 0.0111 |  | 0.0005 | 0.1498 | 0.8526 | 93.0000 |
| category | iid | signflip (30%) | trimmed_mean | 1 | 0.4766 |  | 0.7749 | 0.9839 | 0.0002 | 92.5000 |
| category | iid | signflip (30%) | median | 1 | 0.6646 |  | 0.3072 | 0.9655 | 0.0022 | 92.9000 |
| category | iid | targeted (10%) | fedavg | 1 | 0.5603 |  | 0.5156 | 0.8408 | 0.2914 | 93.3000 |
| category | iid | targeted (10%) | trimmed_mean | 1 | 0.6684 |  | 0.2937 | 0.9662 | 0.0021 | 92.9000 |
| category | iid | targeted (10%) | median | 1 | 0.6676 |  | 0.2902 | 0.9658 | 0.0021 | 93.2000 |
| category | iid | targeted (30%) | fedavg | 1 | 0.4986 |  | 0.5510 | 0.6903 | 0.6366 | 93.2000 |
| category | iid | targeted (30%) | trimmed_mean | 1 | 0.6394 |  | 0.4282 | 0.9679 | 0.0227 | 93.2000 |
| category | iid | targeted (30%) | median | 1 | 0.6631 |  | 0.2839 | 0.9635 | 0.0030 | 93.9000 |
| class34 | iid | No attack | FedAvg | 3 | 0.5195 | 0.0007 | 0.2955 | 0.9602 | 0.0011 | 93.2000 |
| class34 | iid | No attack | Median | 3 | 0.5196 | 0.0007 | 0.2921 | 0.9601 | 0.0011 | 93.2667 |
| class34 | iid | No attack | Trimmed mean | 3 | 0.5203 | 0.0009 | 0.2945 | 0.9601 | 0.0011 | 92.9333 |
| class34 | iid | No attack | Norm clip | 3 | 0.5195 | 0.0008 | 0.2962 | 0.9603 | 0.0011 | 93.1000 |
| class34 | iid | Sign-flip x5 (20 %) | FedAvg | 3 | 0.0031 | 0.0052 | 1.0000 | 1.0000 | 0.0000 | 92.8667 |
| class34 | iid | Sign-flip x5 (20 %) | Median | 3 | 0.5131 | 0.0040 | 0.3104 | 0.9602 | 0.0011 | 93.1333 |
| class34 | iid | Sign-flip x5 (20 %) | Trimmed mean | 3 | 0.5120 | 0.0044 | 0.3133 | 0.9605 | 0.0012 | 93.3667 |
| class34 | iid | Sign-flip x5 (20 %) | Norm clip | 3 | 0.5036 | 0.0049 | 0.3234 | 0.9595 | 0.0012 | 93.6667 |
| class34 | iid | DDoS->Benign boost (20 %) | FedAvg | 3 | 0.3960 | 0.0401 | 0.5701 | 0.8745 | 0.2316 | 93.0667 |
| class34 | iid | DDoS->Benign boost (20 %) | Median | 3 | 0.5220 | 0.0017 | 0.3041 | 0.9608 | 0.0014 | 93.1333 |
| class34 | iid | DDoS->Benign boost (20 %) | Trimmed mean | 3 | 0.5230 | 0.0016 | 0.3047 | 0.9611 | 0.0014 | 93.3667 |
| class34 | iid | DDoS->Benign boost (20 %) | Norm clip | 3 | 0.5175 | 0.0015 | 0.3344 | 0.9639 | 0.0015 | 93.7667 |
| class34 | dir1.0 | No attack | FedAvg | 1 | 0.5198 | 0.0000 | 0.3149 | 0.9616 | 0.0012 | 95.8000 |
| class34 | dir1.0 | No attack | Median | 1 | 0.5209 | 0.0000 | 0.3011 | 0.9593 | 0.0011 | 92.7000 |
| class34 | dir1.0 | No attack | Trimmed mean | 1 | 0.5187 | 0.0000 | 0.2945 | 0.9583 | 0.0012 | 93.1000 |
| class34 | dir1.0 | No attack | Norm clip | 1 | 0.5173 | 0.0000 | 0.3241 | 0.9615 | 0.0012 | 92.7000 |
| class34 | dir1.0 | Sign-flip x5 (20 %) | FedAvg | 1 | 0.0097 | 0.0000 | 1.0000 | 1.0000 | 0.0000 | 92.8000 |
| class34 | dir1.0 | Sign-flip x5 (20 %) | Median | 1 | 0.5041 | 0.0000 | 0.4409 | 0.9752 | 0.0011 | 93.3000 |
| class34 | dir1.0 | Sign-flip x5 (20 %) | Trimmed mean | 1 | 0.5010 | 0.0000 | 0.4604 | 0.9772 | 0.0010 | 92.6000 |
| class34 | dir1.0 | Sign-flip x5 (20 %) | Norm clip | 1 | 0.4932 | 0.0000 | 0.4797 | 0.9768 | 0.0011 | 93.0000 |
| class34 | dir1.0 | DDoS->Benign boost (20 %) | FedAvg | 1 | 0.3214 | 0.0000 | 0.4899 | 0.7774 | 0.4239 | 93.4000 |
| class34 | dir1.0 | DDoS->Benign boost (20 %) | Median | 1 | 0.5162 | 0.0000 | 0.3539 | 0.9658 | 0.0013 | 93.0000 |
| class34 | dir1.0 | DDoS->Benign boost (20 %) | Trimmed mean | 1 | 0.5132 | 0.0000 | 0.3594 | 0.9672 | 0.0014 | 93.2000 |
| class34 | dir1.0 | DDoS->Benign boost (20 %) | Norm clip | 1 | 0.4982 | 0.0000 | 0.3852 | 0.9684 | 0.0018 | 93.8000 |
| class34 | iid | signflip (10%) | fedavg | 1 | 0.4956 |  | 0.3475 | 0.9587 | 0.0013 | 93.3000 |
| class34 | iid | signflip (10%) | trimmed_mean | 1 | 0.5177 |  | 0.2975 | 0.9609 | 0.0010 | 92.6000 |
| class34 | iid | signflip (10%) | median | 1 | 0.5204 |  | 0.3019 | 0.9606 | 0.0010 | 93.4000 |
| class34 | iid | signflip (30%) | fedavg | 1 | 0.0022 |  | 1.0000 | 1.0000 | 0.0000 | 92.8000 |
| class34 | iid | signflip (30%) | trimmed_mean | 1 | 0.3636 |  | 0.7963 | 0.9781 | 0.0012 | 92.9000 |
| class34 | iid | signflip (30%) | median | 1 | 0.5120 |  | 0.3230 | 0.9606 | 0.0011 | 93.5000 |
| class34 | iid | targeted (10%) | fedavg | 1 | 0.4116 |  | 0.7077 | 0.9040 | 0.1971 | 93.4000 |
| class34 | iid | targeted (10%) | trimmed_mean | 1 | 0.5218 |  | 0.3081 | 0.9623 | 0.0011 | 93.5000 |
| class34 | iid | targeted (10%) | median | 1 | 0.5212 |  | 0.3029 | 0.9617 | 0.0011 | 92.9000 |
| class34 | iid | targeted (30%) | fedavg | 1 | 0.2916 |  | 0.6519 | 0.7488 | 0.5139 | 93.8000 |
| class34 | iid | targeted (30%) | trimmed_mean | 1 | 0.4839 |  | 0.4573 | 0.9754 | 0.0071 | 93.5000 |
| class34 | iid | targeted (30%) | median | 1 | 0.5246 |  | 0.3291 | 0.9643 | 0.0015 | 93.2000 |
| binary | iid | No attack | FedAvg | 3 | 0.7411 | 0.0003 | 0.1814 | 0.9440 | 0.0020 | 92.2000 |
| binary | iid | No attack | Median | 3 | 0.7402 | 0.0011 | 0.1766 | 0.9431 | 0.0021 | 92.9000 |
| binary | iid | No attack | Trimmed mean | 3 | 0.7405 | 0.0008 | 0.1785 | 0.9435 | 0.0021 | 92.5667 |
| binary | iid | No attack | Norm clip | 3 | 0.7416 | 0.0003 | 0.1828 | 0.9444 | 0.0020 | 93.0667 |
| binary | iid | Sign-flip x5 (20 %) | FedAvg | 3 | 0.0380 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 92.3667 |
| binary | iid | Sign-flip x5 (20 %) | Median | 3 | 0.7382 | 0.0011 | 0.1817 | 0.9427 | 0.0021 | 92.5667 |
| binary | iid | Sign-flip x5 (20 %) | Trimmed mean | 3 | 0.7386 | 0.0014 | 0.1843 | 0.9432 | 0.0021 | 92.7667 |
| binary | iid | Sign-flip x5 (20 %) | Norm clip | 3 | 0.7381 | 0.0017 | 0.1881 | 0.9434 | 0.0021 | 92.8000 |
| binary | iid | DDoS->Benign boost (20 %) | FedAvg | 3 | 0.5328 | 0.0180 | 0.3940 | 0.7971 | 0.3946 | 92.8333 |
| binary | iid | DDoS->Benign boost (20 %) | Median | 3 | 0.7416 | 0.0017 | 0.1847 | 0.9446 | 0.0024 | 92.8667 |
| binary | iid | DDoS->Benign boost (20 %) | Trimmed mean | 3 | 0.7426 | 0.0005 | 0.1897 | 0.9456 | 0.0023 | 92.9000 |
| binary | iid | DDoS->Benign boost (20 %) | Norm clip | 3 | 0.7472 | 0.0022 | 0.2118 | 0.9499 | 0.0021 | 92.7000 |
| binary | dir1.0 | No attack | FedAvg | 1 | 0.7571 | 0.0000 | 0.2455 | 0.9575 | 0.0017 | 87.7000 |
| binary | dir1.0 | No attack | Median | 1 | 0.7334 | 0.0000 | 0.1783 | 0.9401 | 0.0028 | 88.4000 |
| binary | dir1.0 | No attack | Trimmed mean | 1 | 0.7378 | 0.0000 | 0.1871 | 0.9431 | 0.0024 | 89.0000 |
| binary | dir1.0 | No attack | Norm clip | 1 | 0.7521 | 0.0000 | 0.2284 | 0.9537 | 0.0019 | 89.0000 |
| binary | dir1.0 | Sign-flip x5 (20 %) | FedAvg | 1 | 0.0380 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 87.7000 |
| binary | dir1.0 | Sign-flip x5 (20 %) | Median | 1 | 0.7406 | 0.0000 | 0.2557 | 0.9520 | 0.0034 | 87.5000 |
| binary | dir1.0 | Sign-flip x5 (20 %) | Trimmed mean | 1 | 0.7482 | 0.0000 | 0.3228 | 0.9623 | 0.0030 | 87.4000 |
| binary | dir1.0 | Sign-flip x5 (20 %) | Norm clip | 1 | 0.7417 | 0.0000 | 0.4564 | 0.9750 | 0.0021 | 88.4000 |
| binary | dir1.0 | DDoS->Benign boost (20 %) | FedAvg | 1 | 0.3919 | 0.0000 | 0.0537 | 0.4857 | 0.7340 | 88.2000 |
| binary | dir1.0 | DDoS->Benign boost (20 %) | Median | 1 | 0.7403 | 0.0000 | 0.2211 | 0.9480 | 0.0033 | 88.5000 |
| binary | dir1.0 | DDoS->Benign boost (20 %) | Trimmed mean | 1 | 0.7448 | 0.0000 | 0.2425 | 0.9523 | 0.0032 | 88.7000 |
| binary | dir1.0 | DDoS->Benign boost (20 %) | Norm clip | 1 | 0.7584 | 0.0000 | 0.3277 | 0.9665 | 0.0026 | 88.1000 |
| binary | iid | signflip (10%) | fedavg | 1 | 0.7260 |  | 0.1995 | 0.9390 | 0.0024 | 92.8000 |
| binary | iid | signflip (10%) | trimmed_mean | 1 | 0.7411 |  | 0.1854 | 0.9444 | 0.0017 | 92.0000 |
| binary | iid | signflip (10%) | median | 1 | 0.7389 |  | 0.1826 | 0.9432 | 0.0018 | 92.7000 |
| binary | iid | signflip (30%) | fedavg | 1 | 0.0380 |  | 0.0000 | 0.0000 | 1.0000 | 93.1000 |
| binary | iid | signflip (30%) | trimmed_mean | 1 | 0.7077 |  | 0.3261 | 0.9457 | 0.0048 | 92.3000 |
| binary | iid | signflip (30%) | median | 1 | 0.7352 |  | 0.1703 | 0.9401 | 0.0021 | 92.4000 |
| binary | iid | targeted (10%) | fedavg | 1 | 0.5909 |  | 0.4231 | 0.8788 | 0.2013 | 92.2000 |
| binary | iid | targeted (10%) | trimmed_mean | 1 | 0.7435 |  | 0.1850 | 0.9455 | 0.0017 | 92.2000 |
| binary | iid | targeted (10%) | median | 1 | 0.7419 |  | 0.1826 | 0.9445 | 0.0017 | 93.0000 |
| binary | iid | targeted (30%) | fedavg | 1 | 0.4773 |  | 0.4548 | 0.7161 | 0.5758 | 92.6000 |
| binary | iid | targeted (30%) | trimmed_mean | 1 | 0.7293 |  | 0.3330 | 0.9561 | 0.0158 | 93.1000 |
| binary | iid | targeted (30%) | median | 1 | 0.7427 |  | 0.1917 | 0.9459 | 0.0026 | 93.7000 |
