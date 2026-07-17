# Attack class: goroutine_leak

A goroutine blocks forever on a channel operation or a missing cancellation
and is never reclaimed, so each triggering request leaks a goroutine plus
whatever it holds (memory, sockets, locks). Under attacker-driven request
volume the accumulation becomes a denial of service. The bug is an
unbounded-lifetime goroutine, not merely a long-running one. This class is
Go only.

## What to look for

- **Send/receive with no counterparty.** A goroutine that does `ch <- v` on
  an unbuffered channel whose receiver has already returned (e.g. the caller
  timed out), or `<-ch` on a channel nothing will ever send to. The blocked
  goroutine parks forever.
- **Missing context cancellation.** A per-request goroutine that loops or
  blocks with no `select { case <-ctx.Done(): ... }` and no other exit — so
  when the request is cancelled or the client disconnects, the goroutine
  keeps running.
- **Per-request goroutines with no lifetime bound.** `go handle(req)` started
  on every inbound request with no pool, no cap, and no cancellation path —
  request volume translates directly into goroutine count.
- **`WaitGroup` Add/Done mismatch.** `wg.Add(n)` with fewer than `n` `Done`
  calls on some path, leaving `wg.Wait()` blocked forever (and its goroutine
  with it), or `Add` inside the goroutine racing `Wait`.
- **Leaked tickers/timers.** `time.NewTicker` / `time.NewTimer` whose `Stop`
  is never called on an early-return path, keeping a goroutine and the timer
  alive.

## Evidence

Hunt's v0.3 toolset is `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `record_finding` — there is no `compile_and_run`, so a
finding cannot carry a real execution result. Use `find_definition` and
`find_callers` to trace how untrusted data reaches the sink. A finding should
carry `file`, `function`, `line_start`, `line_end` at the sink plus a
`description` of that flow, and a short **textual** `poc_code` sketch of the
triggering input. Do **not** fabricate a `poc_result` — leave it unset.
Confidence: `likely` when you can trace the flow end-to-end, `speculative`
when a link in the chain is unclear. Do **not** use `confirmed`; it requires
execution Hunt cannot perform in v0.3.

## Common false positives

- The goroutine's lifetime is bounded by `ctx` and it selects on
  `ctx.Done()` (or a done/quit channel) — it exits when the request does.
- A buffered channel that is guaranteed to be drained, or a send that always
  has a live receiver.
- A fixed-size worker pool with a shutdown path, or goroutines joined by a
  correctly balanced `WaitGroup`.
- Tickers/timers stopped via `defer t.Stop()` on every return path.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
