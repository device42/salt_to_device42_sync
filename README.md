# saltexplore
Script to sync Salt nodes information to Device42 (http://device42.com)
This script was tested with Salt Master ( 2016.11.1 Carbon )

# Requirements
Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.

# Salt Configure
For proper connection minions certificate should be signed on salt master.
Script should be runned on salt master server.
See [NodeFilter.md](./NodeFilter.md) for node filtering options.

# Run
```
python saltexplore.py [-c /path/to/settings.yaml]
```

# Command List
```
  -h, --help            show help message and exit
  -d, --debug           Enable debug output
  -q, --quiet           Quiet mode - outputs only errors
  -c CONFIG, --config CONFIG
                        Config file
  -f NODEFILE, --nodefile NODEFILE
                        Get node info from JSON file instead of Salt server
  -S SAVENODES, --savenodes SAVENODES
                        Save nodes info from Salt server to json file
  -n ONLYNODE, --onlynode ONLYNODE
                        Process only selected nodes (fqdn or hostname)
```

# Bugs / Feature Requests

Please attach node info from salt while sending bugs/feature requests. It can help to understand your specifics.
