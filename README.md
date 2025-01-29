# Dual Entropy Random

A production-ready random number generation API that combines NIST Beacon and drand randomness for enhanced entropy.

## Features
- Dual entropy sources (NIST + drand)
- Mersenne Twister (MT19937) implementation
- Serverless-ready
- TypeScript support
- Zero dependencies (except Deno std)

## Quick Start
```bash
# Clone the repository
git clone https://github.com/shuimu5418/dual-entropy-random

# Run locally
deno run --allow-net main.ts
