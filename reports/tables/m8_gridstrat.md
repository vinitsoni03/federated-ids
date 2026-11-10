| features | held_out_llm | test_windows | positive | roc_auc | pr_auc | precision | recall | f1 | session_detection | false_alarm_windows_per_h_normal |
|---|---|---|---|---|---|---|---|---|---|---|
| volume | anthropic/claude-sonnet-4.6 | 1713 | 1105 | 0.9958 | 0.9977 | 0.9886 | 0.9421 | 0.9648 | 1.0000 | 0.0000 |
| volume | google/gemini-3.1-pro-preview | 2251 | 222 | 0.9996 | 0.9974 | 1.0000 | 0.9369 | 0.9674 | 1.0000 | 0.0000 |
| volume | minimax/minimax-m2.5 | 2405 | 692 | 0.9760 | 0.9581 | 0.5040 | 0.9957 | 0.6693 | 1.0000 | 1.4200 |
| volume | openai/gpt-5.3-codex | 1443 | 922 | 0.9035 | 0.9196 | 0.8780 | 0.9056 | 0.8916 | 1.0000 | 0.0000 |
| binding | anthropic/claude-sonnet-4.6 | 1713 | 1105 | 0.9947 | 0.9958 | 0.9934 | 0.9484 | 0.9704 | 1.0000 | 0.0000 |
| binding | google/gemini-3.1-pro-preview | 2251 | 222 | 0.9915 | 0.9881 | 1.0000 | 0.9730 | 0.9863 | 1.0000 | 0.0000 |
| binding | minimax/minimax-m2.5 | 2405 | 692 | 0.9848 | 0.9708 | 0.4500 | 0.9957 | 0.6199 | 1.0000 | 1.4200 |
| binding | openai/gpt-5.3-codex | 1443 | 922 | 0.9355 | 0.9398 | 0.9030 | 0.9089 | 0.9059 | 1.0000 | 0.0000 |
| volume+binding | anthropic/claude-sonnet-4.6 | 1713 | 1105 | 0.9972 | 0.9985 | 0.9915 | 0.9557 | 0.9733 | 1.0000 | 0.0000 |
| volume+binding | google/gemini-3.1-pro-preview | 2251 | 222 | 0.9995 | 0.9970 | 1.0000 | 0.9730 | 0.9863 | 1.0000 | 0.0000 |
| volume+binding | minimax/minimax-m2.5 | 2405 | 692 | 0.9907 | 0.9859 | 0.5938 | 0.9884 | 0.7419 | 1.0000 | 0.0000 |
| volume+binding | openai/gpt-5.3-codex | 1443 | 922 | 0.9177 | 0.9278 | 0.8844 | 0.9295 | 0.9064 | 1.0000 | 0.0000 |
| zeek_only | anthropic/claude-sonnet-4.6 | 1713 | 1105 | 0.7219 | 0.7798 | 0.8694 | 0.6145 | 0.7200 | 0.7652 | 1.4200 |
| zeek_only | google/gemini-3.1-pro-preview | 2251 | 222 | 0.9134 | 0.4243 | 0.4180 | 0.9414 | 0.5789 | 1.0000 | 1.4200 |
| zeek_only | minimax/minimax-m2.5 | 2405 | 692 | 0.6098 | 0.3607 | 0.4025 | 0.5130 | 0.4511 | 0.6102 | 1.4200 |
| zeek_only | openai/gpt-5.3-codex | 1443 | 922 | 0.7675 | 0.8142 | 0.9068 | 0.6540 | 0.7599 | 0.7114 | 1.4200 |
| rule: ip_with_multiple_macs>0 | anthropic/claude-sonnet-4.6 |  |  |  |  |  | 0.9376 |  | 1.0000 | 0.0000 |
| rule: ip_with_multiple_macs>0 | google/gemini-3.1-pro-preview |  |  |  |  |  | 0.9865 |  | 1.0000 | 0.0000 |
| rule: ip_with_multiple_macs>0 | minimax/minimax-m2.5 |  |  |  |  |  | 0.9566 |  | 1.0000 | 0.0000 |
| rule: ip_with_multiple_macs>0 | openai/gpt-5.3-codex |  |  |  |  |  | 0.8937 |  | 1.0000 | 0.0000 |
| rule: arp_packets>0 | anthropic/claude-sonnet-4.6 |  |  |  |  |  | 0.7276 |  | 0.9478 | 358.5800 |
| rule: arp_packets>0 | google/gemini-3.1-pro-preview |  |  |  |  |  | 1.0000 |  | 1.0000 | 358.5800 |
| rule: arp_packets>0 | minimax/minimax-m2.5 |  |  |  |  |  | 0.6676 |  | 0.9322 | 358.5800 |
| rule: arp_packets>0 | openai/gpt-5.3-codex |  |  |  |  |  | 0.7592 |  | 0.9195 | 358.5800 |
| rule: zeek_weird>0 | anthropic/claude-sonnet-4.6 |  |  |  |  |  | 0.6154 |  | 0.7652 | 1.4200 |
| rule: zeek_weird>0 | google/gemini-3.1-pro-preview |  |  |  |  |  | 0.9865 |  | 1.0000 | 1.4200 |
| rule: zeek_weird>0 | minimax/minimax-m2.5 |  |  |  |  |  | 0.5130 |  | 0.6102 | 1.4200 |
| rule: zeek_weird>0 | openai/gpt-5.3-codex |  |  |  |  |  | 0.6562 |  | 0.7114 | 1.4200 |
