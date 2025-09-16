# Cache Eviction on Zen 4 and Zen 5

Experiments for generating and testing LLC eviction sets.

## Reproduce

The experiments can be run either on the host directly or inside our virtual machine.
On the host the _measure\_window.c_ uses RDPRU which allows observing the L1 evictions.
Inside the virtual machine only `rdtsc` and `rdtscp` are available with which this experiment does not observe the L1 evictions.
This leads to the following error being printed when running inside the virtual machine.
```log
target in L1
[ERROR] measure_window.c:369:measure_window_size set not found
```
However, eviction set building works either way so that is not a problem for the experiments, just a limitation to keep in mind when interpreting the results.


### 1) Setup

In order to run the experiments on the host, you need to allocate some 2MB huge pages.
```bash
# enable 2MB hugepages
echo 2048 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
# alternatively, you can add this to the kernel command line instead:
# hugepagesz=2M default_hugepagesz=2M hugepages=2048
```

In order to run the experiment inside a virtual machine, you need to first perform the virtual machine setup (build.sh) in [vmscape](../vmscape/).

### 2) Run the experiments

#### Manual execution

**Host**
```bash
# build the experiments
make clean
make CUSTOM_DEFS=-DRDPRU_AVAILABLE
# for zen 5
# make CUSTOM_DEFS=-DRDPRU_AVAILABLE MARCH=MARCH_ZEN5

# run the experiments
./evict_eval
./measure_window
```

**VM**

First, perform the virtual machine setup (build.sh) in [vmscape](../vmscape/).

```bash
# build the experiments
make clean
make
# for zen 5
# make MARCH=MARCH_ZEN5

# copy the experiments to the VM's shared folder
cp ./evict_eval ./measure_window ../vmscape/attack/

# run the virtual machine
bash ../vmscape/guest/run-vm.sh

# run the experiments
./evict_eval
./measure_window

# to stop the virtual machine, press Ctrl-A, X
```

**Plot**
To plot the window measurement results, we copy the printed arrays into [plot_speculation_window.py](./plot_speculation_window.py) at the line marked with "# MANUAL RESULT ENTRY".

#### Automated evaluation

This experiment evaluates the eviction efficacy automatically
```bash
# run the script for evaluation, it will run the experiment natively and inside the VM
bash evaluate-eviction.sh
# for zen 5
# bash evaluate-eviction.sh --zen5

# analyze the results
python3 data/evict_analyze.py
```
