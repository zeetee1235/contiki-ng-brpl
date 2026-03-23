<img src="https://github.com/contiki-ng/contiki-ng.github.io/blob/master/images/logo/Contiki_logo_2RGB.png" alt="Logo" width="256">

# Contiki-NG BRPL

> **Note**: This repository provides a research implementation of  
> **BRPL (Backpressure RPL)** on top of **RPL Classic** in Contiki-NG.
> It is intended for simulation-based and inspectable routing research.

[![license](https://img.shields.io/badge/license-3--clause%20bsd-brightgreen.svg)](LICENSE.md)

## Purpose

This repository implements **BRPL (Backpressure RPL)** at the routing layer
of Contiki-NG, following the original BRPL paper as closely as possible.

The primary goal of this repository is to provide a **faithful and inspectable
BRPL implementation** for research and simulation, rather than a
production-ready IoT stack.

## Scope

This repository focuses on:

- BRPL parent selection and routing behavior
- Queue-based backpressure routing metrics
- Control-plane extensions (e.g., DIO queue information)
- Hybrid operation with standard RPL nodes

Higher-level experiments such as attack scenarios, observability analysis,
and topology-specific evaluations are maintained in **separate research repositories**.

## Modifications

- **BRPL (Backpressure RPL)** implementation on RPL Classic
- Queue-based backpressure metrics for parent selection
- DIO extensions for propagating queue/backpressure information
- Minimal debugging and validation examples

## Original Contiki-NG

Contiki-NG is an open-source, cross-platform operating system for
next-generation IoT devices. It focuses on dependable (secure and reliable)
low-power communication and standard protocols, such as IPv6/6LoWPAN,
6TiSCH, RPL, and CoAP.

Unless explicitly stated otherwise, Contiki-NG sources are distributed under
the terms of the [3-clause BSD license](LICENSE.md).

## Upstream Contiki-NG Resources

- Upstream repository: https://github.com/contiki-ng/contiki-ng
- Documentation: https://docs.contiki-ng.org/
- Web site: https://contiki-ng.org

## Related Research Project

This implementation is used as the routing substrate for the following research project:

- https://github.com/zeetee1235/TA-BRPL
