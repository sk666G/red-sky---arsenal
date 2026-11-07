# 105c — ROP Stack Spoof Design Pass

**Status:** design. no code shipped in 105c-1. 105c-2 implements against this doc.

**Goal:** during the beacon sleep window, the agent's threads should show
a normal application's call stack to any tool that walks it — EDR, memory
scanner, coredump triage. The stack should look like
kernel32!Sleep -> ntdll!NtWaitForSingleObject instead of
runtime.netpollblock -> runtime.gopark -> runtime.park_m.

**Why this matters:** sliver and CS both ship this. An EDR that scans
thread stacks sees Go's netpoller frames and flags the process before
any payload runs.

## Current state

cmd/redsky-agent/main.go heartbeat goroutine sleeps via
`case <-time.After(sleepFn()):` — internally runtime.timer -> runtime.gopark
-> runtime.netpollblock. When the thread is idle-parked, its stack reads:

    runtime.notetsleepg
    runtime.netpollblock
    runtime.gopark
    runtime.park_m

Any stack walker with a Go-runtime detection heuristic matches immediately.
Thread state via NtQuerySystemInformation is Waiting:Timer, not
Waiting:UserRequest like a normal SleepEx call.

## Three approaches

### Approach A — spoofed stack at syscall boundary (RECOMMENDED)

Push a hand-crafted frame before each sleep so the thread reads:

    RET -> kernel32!SleepEx
    RET -> ntdll!NtWaitForSingleObject
    RET -> ntdll!NtWaitForAlertByThreadId

then wait via NtWaitForSingleObject on a timeout event object. Pop on wake.

Pro: stack walker sees the forged chain. Thread state is
Waiting:UserRequest.

Con: Go runtime walks stacks. Foreign frames break runtime.stackwalk and
the GC panics on scan.

Mitigation: mark the goroutine syscall-exiting via
//go:linkname entersyscall runtime.entersyscall and exitsyscall. Between
those calls the GC treats the thread stack as opaque. No allocations
permitted between the two calls.

### Approach B — DWARF rewrite (REJECTED)

Rewrite existing frames' function names and file/line metadata so a
DWARF-aware unwinder shows kernel32!SleepEx where it sees runtime.gopark.

Pro: no frame layout change.

Con: requires debug/dwarf at runtime, byte-patches .debug_info/.debug_line,
toolchain may strip them. Any Go patch release can break silently. Go
1.26.0 DWARF output already differs from 1.22 in ways that invalidate a
1.22 patch.

### Approach C — Windows Fiber switch (REJECTED)

ConvertThreadToFiber at startup, SwitchToFiber into a hand-built
SleepEx-shaped stack during sleep, SwitchToFiber back on wake.

Pro: Windows-native. Fiber stacks are opaque to the Go GC.

Con: Go runtime does not support running Go code on fibers. Calling
SwitchToFiber from a Go goroutine without exiting the scheduler causes
the scheduler to lose track of the goroutine. Two runtimes fighting for
thread control. Real deadlock/hang risk.

## Recommendation: Approach A

Chain:

1. runtime.LockOSThread() — pin goroutine to specific thread.
2. //go:linkname entersyscall runtime.entersyscall — mark syscall-exiting.
3. Push three fake frames:
     [sp-8]  = kernel32!SleepEx
     [sp-16] = ntdll!NtWaitForSingleObject
     [sp-24] = ntdll!NtWaitForAlertByThreadId
   Real addresses from GetProcAddress(LoadLibraryA(...)).
4. Move rsp down 24 bytes.
5. Call NtWaitForSingleObject on signalled-timeout event.
6. Restore rsp, pop frames.
7. //go:linkname exitsyscall runtime.exitsyscall.
8. runtime.UnlockOSThread().

Forged frames only visible while waiting inside NtWaitForSingleObject.
After wake gone — runtime sees normal stack. GC never scans them because
entersyscall marked the thread opaque.

## Constraints that must not break

- GC. entersyscall state required, fake frames out of scan range, no
  allocations after entersyscall.
- Scheduler. Thread pinned for sleep window. UnlockOSThread on wake.
- Signals. SEH during fake-frame window unwinds forged frames = panic.
  Sleep window is NtWaitForSingleObject on private event, no user code
  runs.
- Panic recovery. Go panic in any other goroutine must not walk this
  thread's stack. entersyscall prevents this.

## Implementation plan for 105c-2

- internal/evasion/spoof_windows.go — SpoofedSleep(d time.Duration) error,
  full chain.
- internal/evasion/spoof_other.go — SpoofedSleep delegates to time.Sleep.
- cmd/redsky-agent/main.go — heartbeat loop swaps time.After for
  SpoofedSleep, guarded by -spoof flag (default on for windows).
- Tests: windows-only integration test asserting thread state is
  Waiting:UserRequest via NtQuerySystemInformation. Plus a GC stress
  test — 10 spawns, 10 spoofed sleeps, no panic.

## Risks

- //go:linkname fragility on Go major bumps. Pin toolchain in go.mod.
  Treat any Go update as a fresh test cycle.
- Windows-only. Linux needs a separate ticket with ptrace/proc approach.
- Race-detector builds (-race) change stack layout. Must be gated.

## Out of scope

- Signal handler frames from other threads (OS-handled).
- Kernel-mode stacks (ETW looks at those, not user-mode).
- Full ROP chain spoof (RetSpoofStub style). 3 fake return addresses
  defeat simple stack walkers. Sophisticated walkers with instruction
  alignment checks need a separate track.
