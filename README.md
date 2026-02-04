<img src="https://github.com/contiki-ng/contiki-ng.github.io/blob/master/images/logo/Contiki_logo_2RGB.png" alt="Logo" width="256">

# Contiki-NG BRPL Fork

> **Note**: This is a fork of Contiki-NG specifically for BRPL (Backup RPL) experiments and RPL attack observability research.

[![license](https://img.shields.io/badge/license-3--clause%20bsd-brightgreen.svg)](https://github.com/contiki-ng/contiki-ng/blob/master/LICENSE.md)

## Purpose

This repository is maintained for the **RPL Structural Attack Observability** research project. It includes:

- Custom firmware for RPL/BRPL network simulations
- Selective forwarding attack implementations
- Structured logging for observability analysis (`logging_spec.md` format)
- Cooja simulation configurations for topology experiments

## Modifications

- **BRPL Support**: Enhanced BRPL (Backup RPL) routing protocol implementations
- **Attack Nodes**: Configurable selective forwarding attack behavior with attack rate α
- **Structured Logging**: Printf-based logging in `OBS key=value` format for automated parsing
- **Experimental Scenarios**: Support for Star, Chain/Tree, Mesh, and BRPL adaptive topologies

## Original Contiki-NG

Contiki-NG is an open-source, cross-platform operating system for Next-Generation IoT devices. It focuses on dependable (secure and reliable) low-power communication and standard protocols, such as IPv6/6LoWPAN, 6TiSCH, RPL, and CoAP.

Unless explicitly stated otherwise, Contiki-NG sources are distributed under
the terms of the [3-clause BSD license](LICENSE.md).

## Upstream Contiki-NG Resources

* Upstream repository: https://github.com/contiki-ng/contiki-ng
* Documentation: https://docs.contiki-ng.org/
* Web site: http://contiki-ng.org

## Related Research Project

This fork is part of: https://github.com/zeetee1235/rpl-structural-attack-observability
