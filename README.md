# Wireshark Dissector for Radio Link Simulation Protocol from UERANSIM

## Installation
### Requirements
You need to use a recent Wireshark version with implementation for `nr-rrc` dissectors (Wireshark version 3.0.0 at least).

### Installation from git repository
```
$ mkdir -p ${XDG_LIB_HOME:-~/.local/lib}/wireshark/plugins
$ git -C ${XDG_LIB_HOME:-~/.local/lib}/wireshark/plugins clone https://github.com/nextmn/RLS-wireshark-dissector

```
### Installation from package manager
Alternalively, if you are using **Debian Bullseye**, I made a `.deb` package. It is available at [deb-royer.irit.fr](https://deb-royer.irit.fr/) (repository installation instuctions are on the website itself) under the name `wireshark-ueransim-rls`. This package may not work if you have build yourself and installed Wireshark from source (because plugins folder path may not be the same).

## License
This plugin is licensed under the Creative Commons Zero v1.0 Universal licence (CC0-1.0).

## Troubleshooting
If you have any issue running this plugin, please consult the [Troubleshooting page](https://github.com/nextmn/RLS-wireshark-dissector/wiki/Troubleshooting) on the wiki.
