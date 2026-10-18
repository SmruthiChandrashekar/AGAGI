# AGAGI Evaluation Report

## Summary

| Metric | Result |
|---|---|
| Correct verdicts | 100% (6/6) |
| Real issues detected | 100% (4/4) |
| Root cause in the right file | 100% (4/4) |
| Fix proposed for the right file | 100% (4/4) |
| Approved fixes that verified | 100% (4/4) |
| False alarms on clean change | 0% (0/1) |
| Scenarios where AI calls failed | 0/6 |
| Average seconds per review | 46.6s |

## Per scenario

| Branch | Verdict | Verdict OK | Issue found | Root cause OK | Patches | Verified | Tries | AI errors | Time |
|---|---|---|---|---|---|---|---|---|---|
| clean-merge | safe | yes | n/a | n/a | 0 | n/a | 0 | 0 | 13.1s |
| breaks-test | needs_changes | yes | yes | yes | 1 | yes | 1 | 0 | 39.1s |
| conflict | blocked | yes | n/a | n/a | 0 | n/a | 0 | 0 | 26.4s |
| build-error | needs_changes | yes | yes | yes | 1 | yes | 1 | 0 | 43.8s |
| unsafe-eval | needs_changes | yes | yes | yes | 1 | yes | 1 | 0 | 87.8s |
| hardcoded-secret | blocked | yes | yes | yes | 1 | yes | 1 | 0 | 69.6s |
