# Install az-port

`az-port` should be used as a global CLI:

```bash
az-port list
az-port check
az-port suggest
```

The repo-local pattern (`./az-port`, `.\az-port.exe`) is still valid for development, but it should not be the primary user experience.

## Recommended Install Flow

1. Open the latest release on GitHub:
   `https://github.com/ErdemSusam23/az-port/releases`
2. Download the archive that matches your OS.
3. Extract the binary.
4. Move the binary into a directory that is already on your `PATH`, or add a dedicated bin directory to `PATH`.
5. Open a new terminal and run:

```bash
az-port --help
```

Current release artifact names:

- `az-port_Windows_x86_64.zip`
- `az-port_Linux_x86_64.tar.gz`
- `az-port_macOS_x86_64.tar.gz`
- `az-port_macOS_arm64.tar.gz`
- `checksums.txt`

## Windows

Create a personal bin directory if you do not already have one:

```powershell
New-Item -ItemType Directory -Force "$HOME\\bin"
```

Extract the release archive and copy `az-port.exe` into that directory:

```powershell
Copy-Item .\az-port.exe "$HOME\\bin\\az-port.exe" -Force
```

Add the directory to the user `PATH` once:

```powershell
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$HOME\\bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$HOME\\bin", "User")
}
```

Close and reopen PowerShell, then verify:

```powershell
az-port list
```

## Linux

Extract the tarball and move the binary to `/usr/local/bin`:

```bash
tar -xzf az-port_Linux_x86_64.tar.gz
sudo install -m 0755 az-port /usr/local/bin/az-port
```

Verify:

```bash
az-port list
```

## macOS

Extract the archive that matches your CPU:

- Apple Silicon: `az-port_macOS_arm64.tar.gz`
- Intel: `az-port_macOS_x86_64.tar.gz`

Install globally:

```bash
tar -xzf az-port_macOS_arm64.tar.gz
sudo install -m 0755 az-port /usr/local/bin/az-port
```

Verify:

```bash
az-port list
```

## Install From Source

If you want the latest source version instead of a release artifact:

```bash
go install github.com/ErdemSusam23/az-port@latest
```

Go will place the binary in your Go bin directory. Make sure that directory is on your `PATH`.

You can also build locally and move the binary into a global bin directory yourself:

```bash
go build -o az-port
```

## Distribution Strategy

The intended rollout order is:

1. GitHub Releases as the primary install channel
2. Clear PATH-based install instructions
3. Package managers later (`Scoop`, `Chocolatey`, `Homebrew`)

That keeps the release story simple while still giving developers a clean global CLI experience immediately.
