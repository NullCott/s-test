# Network Segmentation Testing Script for PCI DSS Compliance 

#### Requirements

- Linux OS
- Python3 
- Termcolor python3 
- nmap 
- Execution with sudo privileges
- A SJON file with the following structure: 
```json 
{
    "10.10.10.0/32": {
        "target": "10.10.10.10",
        "decoys": ["192.168.0.2", "192.168.0.3", "192.168.0.4"]
    },
    "192.168.1.0/24": {
        "target": "192.168.1.1",
        "decoys": ["192.168.1.2", "192.168.1.3", "192.168.1.4"]
    }
}

```

#### Execution

```bash
sudo python3 network_segmentation_testing.py --file scope.json --attacks all
```
