# Bootstrap format

`bootstrap.cpp` builds a native ARM64 console executable with the static MSVC runtime (`/MT`). It requires Windows PowerShell 5.1 and `bcrypt.lib`; it does not require another archiver or framework installation. Build it as `packaging/bin/tg-woa-sfx.exe` with an `asInvoker` manifest.

The generated installer consists of these bytes, in order:

1. The bootstrap PE.
2. A ZIP payload whose root contains `Install-Package.ps1`.
3. A 56-byte footer: the exact 16 ASCII bytes `TGWOA-SFX-ZIP-v1`, an unsigned 64-bit little-endian ZIP byte length, and the 32 raw bytes of the ZIP's SHA-256 digest.

The footer must be the last bytes of the file. The SHA-256 value detects corruption; it does not provide publisher authentication or replace an Authenticode signature.

Runtime options:

- No arguments: verify and extract to a fresh random temporary folder, then invoke `Install-Package.ps1` there. That script owns elevation, persistent installation, and rollback state.
- `--verify`: verify the footer, digest, ZIP paths, metadata, and decompression lengths without installing or extracting payload files.
- `--extract <new-directory>`: verify and extract without invoking the installer. The local-drive destination must not already exist.
- `--help`: show usage.

The bootstrap creates a new random temporary working folder containing `payload.zip` and its fixed extractor script. Working files are retained and their path is printed. It never performs recursive deletion. ZIP entries are limited to 4096, 256 MiB compressed, 128 MiB per file, and 512 MiB uncompressed overall. Traversal, links/reparse entries, Windows device names, alternate streams, duplicate paths, and file/directory collisions are rejected before extraction. Files use `CreateNew`, so extraction does not overwrite existing files.

Child process arguments use Windows argument quoting and a fixed `-File` entry. Payload paths are passed as parameters rather than interpolated into PowerShell source. No credentials are accepted as bootstrap arguments.
