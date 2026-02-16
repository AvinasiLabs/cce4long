# image-bootstrap

CVM image bootstrapping configuration. This is not a Rust crate.

Contains systemd unit files and scripts that initialize the Computing Plane
environment inside a Confidential VM.

The CP runs as a single `tee-agent` process that internally orchestrates
storage mounting and algorithm execution.

## Structure

```
image-bootstrap/
├── README.md
└── systemd/
    └── tee-agent.service
```
