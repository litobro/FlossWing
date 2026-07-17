# Attack class: path_traversal

Untrusted input is used to build a filesystem path that is then read,
written, or served, and the constructed path can escape the intended
base directory — via `../` sequences, an absolute path that replaces
the base, or a symlink that points outside it. The bug lives at the
boundary where attacker data becomes a path handed to a filesystem
API without being canonicalized-then-checked against the base. The
archive-extraction variant (zip-slip / tar-slip) is the same bug: an
entry name inside an archive contains `../` and the extractor writes
outside the extraction root.

## What to look for

A path segment that traces back to attacker-controlled input (HTTP
route params, query strings, form fields, uploaded filenames, archive
entry names, IPC messages) is joined onto a base directory and passed
to an open/read/write/serve sink without a post-join containment check.

- **Python.** `open(...)`, `os.path.join(base, user)` where `user` is
  attacker data, `pathlib.Path(base) / user`, `send_file` /
  `send_from_directory` / `FileResponse` with a user segment, and
  `shutil`/`zipfile`/`tarfile` extraction loops that trust member
  names.
- **JavaScript / Node.** `fs.readFile`/`fs.createReadStream`/`fs.writeFile`,
  `path.join(base, req.params.x)`, `res.sendFile(userPath)`, and
  archive libraries (`unzipper`, `tar`, `adm-zip`) writing entries by
  their embedded names.
- **Go.** `os.Open`/`os.ReadFile`/`os.Create`, `filepath.Join(base, user)`,
  `http.ServeFile(w, r, userPath)`, and `archive/zip` / `archive/tar`
  loops that `filepath.Join(dest, header.Name)` without checking the
  result stays under `dest`.
- **Java.** `new File(base, user)`, `Files.newInputStream`/`Files.write`,
  `getResourceAsStream` with a user segment, `ServletContext.getResource`,
  and `ZipInputStream`/`ZipEntry.getName()` extraction.
- **C / C++.** `fopen`/`open` with a path composed from user input;
  `snprintf(buf, ..., "%s/%s", base, user)` then opened directly.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. A finding
should carry `file`, `function`, `line_start`, `line_end` at the
sink; a `description` tracing where the path segment enters and why no
canonicalize-then-verify step guards it; and a `poc_code` string
showing the traversal input (e.g. `../../etc/passwd` or an absolute
path). A self-contained `compile_and_run` PoC that constructs the
sink over a scratch base dir and demonstrates a read outside it earns
`confidence=confirmed` (attach `poc_result`). Trace the segment
end-to-end without executing → `likely`. If reachability of the sink
with attacker data is unclear → `speculative`.

## Common false positives

- The path is canonicalized (`realpath`/`Path.resolve`/`filepath.Abs`+
  `filepath.Clean`) AND then verified to start with the base dir before
  use. This is the safe shape — do not report it.
- Only a strict allowlist of fixed names is ever joined onto the base.
- The user value is a database key or opaque id later mapped to a path
  the program controls, never used as a path segment itself.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
