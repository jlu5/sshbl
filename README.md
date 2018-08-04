# SSHBL

SSHBL is an anti-spam tool inspired by [kaniini/antissh](https://github.com/kaniini/antissh), in response to a new wave of IRC spam in 2018. It checks SSHd versions provided in SSH banners against a blacklist, since many compromised hosts are running ancient SSHd versions (e.g. dropbear from 5-10 years ago) with insecure credentials.

The hope is that this can be a useful tool working in conjunction with DNS blacklists and antissh.

## Usage
