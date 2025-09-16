# Gadget scanner

We used this scanner to find our gadget chain for the exploit.

To find the first link in the gadget chain, we set `ENABLE_FR = False` and `ENABLE_JOP = True`. Then we run the scanner:
```bash
python3 gadg3.py "$(which qemu-system-x86_64)"
```

We then manually looked at the resulting gadgets to find a suitable gadget and selected one. In a next step, we updated `INITIAL_REGISTER_STATE` with the new register state after said gadget would be executed. We also set `ENABLE_FR = True` and 
`ENABLE_JOP = False` before running the scanner again:
```bash
python3 gadg3.py "$(which qemu-system-x86_64)"
```