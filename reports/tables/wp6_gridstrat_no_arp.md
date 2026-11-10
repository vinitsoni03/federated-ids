| feature_set | held_out_llm | n_features | roc_auc | recall | precision | session_detection | false_alarms_per_hour | top_features |
|---|---|---|---|---|---|---|---|---|
| volume_m8_reference | anthropic/claude-sonnet-4.6 | 14 | 0.996 | 0.942 | 0.989 | 1.000 | 0.000 | s7_iat_mean, n_s7, s7_iat_std |
| volume_m8_reference | google/gemini-3.1-pro-preview | 14 | 1.000 | 0.937 | 1.000 | 1.000 | 0.000 | s7_iat_mean, bytes, s7_iat_std |
| volume_m8_reference | minimax/minimax-m2.5 | 14 | 0.976 | 0.996 | 0.504 | 1.000 | 1.420 | s7_iat_mean, bytes, n_s7 |
| volume_m8_reference | openai/gpt-5.3-codex | 14 | 0.903 | 0.906 | 0.878 | 1.000 | 0.000 | s7_iat_mean, n_s7, bytes |
| timing_volume_noid | anthropic/claude-sonnet-4.6 | 12 | 0.993 | 0.925 | 0.986 | 1.000 | 0.000 | s7_iat_mean, n_s7, s7_iat_std |
| timing_volume_noid | google/gemini-3.1-pro-preview | 12 | 0.996 | 0.950 | 0.995 | 1.000 | 0.000 | s7_iat_mean, bytes, s7_iat_std |
| timing_volume_noid | minimax/minimax-m2.5 | 12 | 0.969 | 0.988 | 0.482 | 1.000 | 1.420 | s7_iat_mean, n_s7, n_packets |
| timing_volume_noid | openai/gpt-5.3-codex | 12 | 0.896 | 0.893 | 0.868 | 0.980 | 0.000 | s7_iat_mean, n_s7, s7_iat_std |
| process | anthropic/claude-sonnet-4.6 | 137 | 0.501 | 0.344 | 0.681 | 0.826 | 96.760 | std.scada/wind.monitor.temperature_a, range.scada/wind.monitor.temperature_b, range.scada/wind.monitor.temperature_a |
| process | google/gemini-3.1-pro-preview | 137 | 0.373 | 0.239 | 0.061 | 0.537 | 129.490 | range.scada/wind.monitor.temperature_a, std.scada/wind.monitor.temperature_a, range.scada/wind.monitor.temperature_b |
| process | minimax/minimax-m2.5 | 137 | 0.545 | 0.542 | 0.313 | 0.941 | 172.170 | range.demand.monitor.demand, std.demand.monitor.demand, range.scada/wind.monitor.temperature_a |
| process | openai/gpt-5.3-codex | 137 | 0.580 | 0.424 | 0.697 | 0.872 | 78.260 | range.demand.monitor.demand, std.demand.monitor.demand, std.scada/wind.monitor.temperature_a |
| timing_volume_noid+process | anthropic/claude-sonnet-4.6 | 149 | 0.980 | 0.931 | 0.947 | 1.000 | 0.000 | s7_iat_mean, n_s7, bytes |
| timing_volume_noid+process | google/gemini-3.1-pro-preview | 149 | 0.997 | 0.919 | 1.000 | 1.000 | 0.000 | s7_iat_mean, n_s7, bytes |
| timing_volume_noid+process | minimax/minimax-m2.5 | 149 | 0.908 | 0.993 | 0.448 | 1.000 | 1.420 | s7_iat_mean, n_s7, n_packets |
| timing_volume_noid+process | openai/gpt-5.3-codex | 149 | 0.908 | 0.876 | 0.877 | 0.987 | 0.000 | n_s7, s7_iat_mean, bytes |
