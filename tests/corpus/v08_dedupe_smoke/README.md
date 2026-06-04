# dedupe-smoke

Tiny CLI wrapper that runs shell commands on a user-supplied path.
Used for FlossWing's v0.8 dedupe-smoke integration corpus: Hunt is
expected to land at least two `command_injection` findings in the
same function within ±5 lines so Pass 1 of Dedupe deterministically
clusters them.
