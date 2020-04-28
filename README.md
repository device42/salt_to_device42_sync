# saltexplore
Script to sync Salt nodes information to Device42 (http://device42.com)
This script was tested with Salt Master ( 2016.11.1 Carbon )

# Requirements
* Python 3.6.x +
* Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.
* Install needed dependencies by running the following in the project directory

```python
pip3 install -r requirements.txt
```

# Salt Configure
For proper connection minions certificate should be signed on salt master.
Script should be run on salt master server.
See [NodeFilter.md](./NodeFilter.md) for node filtering options.

# Run
```
python3 saltexplore.py [-c /path/to/settings.yaml]
```

# Notes
Importing and using LocalClient must be done on the same machine as the Salt Master and it must be done using the same user that the Salt Master is running as.

More information on the salt.client module can be found [here](https://docs.saltstack.com/en/latest/ref/clients/#localclient)

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
