# VMScape: Exposing and Exploiting Incomplete Branch Predictor Isolation in Cloud Environments

|                     |                                                                      |
| ------------------- | -------------------------------------------------------------------- |
| **Authors:**        | Jean-Claude Graf[^1], Sandro Rüegge[^1], Ali Hajiabadi, Kaveh Razavi |
| **Organization:**   | ETH Zürich                                                           |
| **Published at:**   | 47th IEEE Symposium on Security and Privacy                          |
| **Webpage:**        | https://comsec.ethz.ch/vmscape                                       |
| **Paper:**          | https://comsec-files.ethz.ch/papers/vmscape_sp26.pdf                 |

[^1] Equal contribution joint first authors

## Introduction

VMScape ([CVE-2025-40300](https://www.cve.org/CVERecord?id=CVE-2025-40300)) brings Spectre branch target injection (Spectre-BTI) to the cloud, revealing a critical gap in how branch predictor states are isolated in virtualized environments.
Our systematic analysis of protection-domain isolation shows that current mechanisms are too coarse-grained:
On all AMD Zen CPUs, including the latest Zen 5, the branch predictor cannot distinguish between host and guest execution, enabling practical cross-virtualization BTI (vBTI) attack primitives.
Although Intel's recent CPUs offer better isolation, gaps still exist.

This repository contains the artefacts for VMScape.

> [!NOTE]
> This repository is still work-in-progress. More information, helper scripts and instructions will be added over the next few days.

# Requirements

**OS:** Ubuntu (all work was done on 24.04, but other versions may also work)

## Microarchitectures

> [!todo] To be added

## Dependencies

> [!todo] To be added

## Overview

This repository contains three main parts and is structured as follows:

```
vmscape
|- benchmark        # Ansible tools to run experiments consistently
|- cache-eviction   # Cache eviction experiments
|- poc              # The PoCs we used for the Systematic analysis
|- uARF             # The framework we used to do the reverse engineering and attack
\- vmscape          # Our end-to-end exploit leaking QEMU secrets on Zen 4 and Zen 5. 
```

### PoC
> The PoCs we used for the Systematic analysis

See [[./poc/README.md]] for more information.

### VMScape
> Out end-to-end exploit leaking QEMU secrets on Zen 4 and Zen 5.

See [[./poc/README.md]] for more information.

### Benchmarks
> Scripts and benchmarks outputs for evaluating different mitigations.

See [[./poc/README.md]] for more information.

## Citation

> **_NOTE:_** TODO

> [!todo] To be added
