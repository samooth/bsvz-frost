# Lessons learned — Session 4

WASM/JS documentation pass, DKG identifiable-abort ABI bug, and multi-toolchain
(Zig 0.16.0 / 0.17.0) verification. Builds on Session 3 (Zcash byte-compat).

## WASM boundary: out-slot error semantics are an ABI

9. **Identifiable abort must not set `frost_out_err`.** `frost_dkg_part2` /
   `frost_dkg_part3` returned the cheater count as both the status **and**
   `out_err`. The JS wrapper's `readOut()` checks `out_err !== 0` first, so it
   threw a mis-coded `FrostError` (code = cheater count, e.g. `1` =
   `INVALID_MIN_SIGNERS`) before ever parsing the out-slot — the documented
   `IDENTIFIABLE_ABORT` (27) path was unreachable. Rule: on cheaters,
   `out_err` stays `0` and only the **return code** carries the count; the
   out-slot is `[count u16 BE][count × id32]`. On real errors, return code
   and `out_err` are both the `WasmError` code.
10. **Return-code table must be written down in the module doc comment.**
    The original comment said "`<0` = error code" while every error path
    returns a **positive** enum value (`1`–`28`, `127`). Docs that disagree
    with the ABI are worse than no docs — fix the comment in the same commit
    as the behavior fix.
11. **One global out-slot ⇒ copy-before-next-op is mandatory.** Any host that
    keeps a view across calls, or caches `memory.buffer` across an alloc,
    gets clobbered results. The JS wrapper's `readOut()` slices into a fresh
    `Uint8Array` for this reason; document it for raw-ABI users too.
12. **Unseeded wasm CSPRNG returns zeros.** `wasm32-freestanding` has no OS
    entropy; `frost_random_bytes` fills with `0` until `frost_seed` runs.
    Host seeding is a security requirement, not an optimization — call it out
    in security notes, getting-started, and the ABI chapter.

## Zig 0.16.0 stable vs 0.16.0-dev vs 0.17.0

13. **`std.testing.fuzz` callback signature changed between `0.16.0-dev` and
    stable `0.16.0`.** Dev snapshot (`0.16.0-dev.2535`):
    ```zig
    fn (Allocator, []const u8) anyerror!void
    ```
    Stable `0.16.0` and `0.17.0-dev`: 
    ```zig
    fn (Allocator, *std.testing.Smith) anyerror!void
    ```
    `@hasDecl(std.testing, "Smith")` is the reliable probe — the type does not
    exist on the old API. CI's matrix is `["0.16.0", "master"]`, so a codebase
    developed only on a pre-stable dev snapshot **will fail CI** on the fuzz
    binary even when every protocol test passes.
14. **`Smith` dual-compat pattern** (works on both APIs):
    ```zig
    const has_smith = @hasDecl(std.testing, "Smith");
    const FuzzInput = if (has_smith) *std.testing.Smith else []const u8;

    fn inputBytes(input: FuzzInput, buf: []u8) []const u8 {
        if (comptime has_smith) {
            if (input.in) |in| { /* drain corpus */ ... }
            input.bytes(buf);    // coverage-fuzz mode (in == null)
            return buf;
        }
        return input[0..@min(input.len, buf.len)];
    }
    ```
    - When `smith.in != null` (unit-test / corpus smoke): copy from `in`.
    - When `smith.in == null` (`builtin.fuzz`): call `smith.bytes(buf)` —
      reading `.in` directly is wrong (null) and `unreachable` paths in
      Smith fire if you bypass its generators.
    - The `else` branch must still *mention* `buf` (e.g. `@min(..., buf.len)`)
      or Zig reports an unused parameter after comptime elimination;
      `_ = buf` alone can trip "pointless discard of function parameter".
15. **Toolchain directory names are not trustworthy — always `zig version`.**
    On the machine used for this session the PATH compiler reported
    `0.16.0-dev.2535+b5bd49460` (old fuzz API) while a folder named
    `0.16.0` held stable `0.16.0` and a folder named `0.17.0` held
    `0.17.0-dev.1662+cc6f42302`. Probe each binary before asserting support;
    do not assume a path or folder name matches the actual version.
16. **Verify the full matrix before claiming support:** Debug test, ReleaseFast
    (CI mode; fuzz binary is *skipped* in ReleaseFast/ReleaseSmall by
    `build.zig`), ReleaseSafe, `zig build run`, `zig build wasm
    -Doptimize=ReleaseSmall`, and `npm test` against a wasm built by *each*
    toolchain. One green PATH run does not imply stable/master are green.
17. **`zig fmt` rewrites slice spacing** (`off..off+4` → `off .. off + 4`)
    and multi-arg function parameter layout. Run `zig fmt --check src/ tests/
    build.zig` in the same gate as tests; format-only diffs are fine to ride
    along with a real fix but should be called out in the commit message.

## Docs hygiene (this session)

18. **Docs drift is silent.** Requirements still said `0.16.0-dev.2535`
    after the project actually needed stable `0.16.0`; test counts said
    "45 / 13 unit" when Debug runs **48 / 16 unit** (ReleaseFast = 45 because
    fuzz is compiled out). Audit counts against a live `--summary all`, not
    memory, whenever toolchains or test files change.
19. **Split commits by concern.** ABI/behavior fix (`e770bdc`) ≠ docs-only
    chapter add (`03060f3`) ≠ multi-version fuzz fix + doc refresh
    (`31497da`). Reviewers can revert one without undoing the others.
20. **New numbered LESSONS file per session** — LESSONS_1..3 already exist;
    append to a new `LESSONS_4.md` rather than rewriting history. These files
    are internal working notes, not published docs (not linked from README /
    `docs/`, not in `.gitignore` either).
