# MIFA: An MILP based Framework for Improving Differential Fault Attacks

This repository contains the official implementation of the paper **MIFA: An MILP based Framework for Improving Differential Fault Attacks**.

## Overview
MIFA is an automated framework that utilizes Mixed Integer Linear Programming (MILP) solvers to systematically search for differential trails with a single solution. By evaluating the uniqueness of differential trails, MIFA enables Differential Fault Attacks (DFA) on deeper rounds of block ciphers than previously achieved, significantly reducing the number of required fault injections.

This repository includes the MILP modeling and key recovery simulation codes for the **DEFAULT** block cipher (Simple and Rotating Key Schedules) under the single bit flip fault model.

## Prerequisites
To run the codes in this repository, you will need the following dependencies:
* **Python 3.x**
* **Gurobi Optimizer**: The MILP models are solved using Gurobi. You must have a valid Gurobi license (academic licenses are freely available). The experiments in the paper were conducted using Gurobi 11.0.0 on Ubuntu 22.04 LTS.
