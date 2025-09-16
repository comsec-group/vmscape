# VMScape: Exposing and Exploiting Incomplete Branch Predictor Isolation in Cloud Environments

This repository contains all artefacts for our research paper *"VMScape: Exposing and Exploiting Incomplete Branch Predictor Isolation in Cloud Environments"*.
It contains all resources necessary to reproduce and further explore our work.

VMScape ([CVE-2025-40300](https://www.cve.org/CVERecord?id=CVE-2025-40300)) brings Spectre branch target injection (Spectre-BTI) to the cloud, revealing a critical gap in how branch predictor states are isolated in virtualized environments.
Our systematic analysis of protection-domain isolation shows that current mechanisms are too coarse-grained:
On all AMD Zen CPUs, including the latest Zen 5, the branch predictor cannot distinguish between host and guest execution, enabling practical cross-virtualization BTI (vBTI) attack primitives.
Although Intel's recent CPUs offer better isolation, gaps still exist.

> [!NOTE]
> This repository is still work-in-progress. More information, helper scripts and instructions will be added over the next few days.

  |                     |                                                                                         |
  | ------------------- | --------------------------------------------------------------------------------------- |
  | **Authors:**        | Jean-Claude Graf, Sandro Rüegge, Ali Hajiabadi, Kaveh Razavi                            |
  | **Organization:**   | ETH Zürich, [COMSEC Group](https://comsec.ethz.ch/)                                     |
  | **Published at:**   | [47th IEEE Symposium on Security and Privacy](https://www.ieee-security.org/TC/SP2026/) |
  | **Webpage:**        | <https://comsec.ethz.ch/vmscape>                                                        |
  | **Paper:**          | <https://comsec-files.ethz.ch/papers/vmscape_sp26.pdf>                                  |

## Overview

> ![IMPORTANT]
> All work was conducted on Ubuntu 24.04, and functionality has only been verified on this version.

Our artefacts are structured as follows:

- **[e2e Exploit VMScape](vmscape/README.md):** The end-to-end exploit leaking QEMU secrets on Zen 4 and Zen 5, as described in our §8 of our paper.

- **[vBTI Analysis](vbti_analysis/README.md):** The systematic analysis testing domain isolation in virtualised environments, as described in §5 of our paper.

- **[Benchmarks](benchmarks/README.md):** Our scripts to benchmark the mitigations, as described in §9.2 of our paper.

- **[uARF](uARF/README.md):** Our custom reverse-engineering and exploitation library.

## Citing our Paper

Please use the following BibTeX entry to cite our work:

```bib
@inproceedings{graf_vmscape_2026,
 title = {{VMScape: Exposing and Exploiting Incomplete Branch Predictor Isolation in Cloud Environments}},
 author = {Graf, Jean-Claude and Rüegge, Sandro and Hajiabadi, Ali and Razavi, Kaveh},
 booktitle = {Proceedings of the 2026 IEEE Symposium on Security and Privacy (SP)},
 year = {2026},
 month = may,
 booktitle = {{S\&P}},
}
```
