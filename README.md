# Wireshark Dissector for Radio Link Simulation Protocol from UERANSIM

## Quick Start
```
$ mkdir -p ${XDG_LIB_HOME:-~/.local/lib}/wireshark/plugins
$ git -C ${XDG_LIB_HOME:-~/.local/lib}/wireshark/plugins clone https://github.com/louisroyer/RLS-wireshark-dissector

```

NB: you need to use a recent Wireshark version with implementation for `nr-rrc` dissectors (Wireshark version 3.0.0 at least).
