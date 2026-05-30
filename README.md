# Python Data Infrastructure & Architecture Sandbox

This repository is dedicated to benchmarking high-performance Linux kernel network stacks (BBR congestion control algorithms) and analyzing dynamic multi-threaded HTTP performance using Python's native concurrent servers.

## Core Features Under Test
* Linux Kernel Network Tuning (`sysctl` network buffers optimization)
* Asynchronous event-driven log sniffing simulation
* Gateway reverse-proxy routing via custom upstream pipelines
* Automated scheduling workflows using GitHub Actions runner infrastructure

## Local Setup & Benchmarking
To test the environment simulation locally on an Ubuntu instance:
```bash
python3 analytics_worker.py
