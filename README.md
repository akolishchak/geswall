# GeSWall

GeSWall is a Windows intrusion prevention system that isolates untrusted
applications and enforces policy rules through a kernel-mode driver and
user-mode services and UI.

## Components
- Kernel-mode driver that mediates file, process, and network operations
  (`gswdrv`).
- Windows service that hosts the policy engine and RPC server (`gswserv`).
- Tray UI and notification windows (`gswui`).
- MMC snap-in for administration (`gswmmc`).
- Explorer shell extension with overlays and context actions (`gswshext`).
- Group Policy extension (`gswgp`).
- SQLite-backed policy database and storage layer (`db`).
- Shared code and interfaces (`commonlib`, `gsw`, `interface`, `config`, `ids`,
  `app`).

## Repository layout
- app/ - application and rule models used for policy population.
- commonlib/ - shared utilities (threads, crypto, registry, RPC support).
- config/ - configuration helpers (Windows registry).
- db/ - SQLite schema, storage layer, and tests.
- gsw/ - shared definitions (IOCTLs, rule types).
- gswdrv/ - kernel driver.
- gswgp/ - Group Policy extension.
- gswmmc/ - MMC snap-in.
- gswserv/ - Windows service and RPC server.
- gswshext/ - Explorer shell extension.
- gswui/ - tray UI.
- ids/ - pattern matching utilities.
- interface/ - RPC IDL and client helpers.

## Build overview (Windows only)
This codebase uses Visual Studio .sln/.vcproj projects (VS .NET 2002/2003 era)
and the Windows DDK/WDK build system for the driver.

Prerequisites
- Visual Studio with legacy VC++ project support.
- Windows DDK/WDK with environment variables such as `W2KBASE`, `WXPBASE`,
  `WNETBASE`, or `WLHBASE` configured (see `gswdrv/ddkbuild.cmd`).
- Third-party dependencies referenced by the projects, typically under `lib/`
  with outputs under `lib/build/` (boost, zlib, sqlite, ltmc).
- Some solutions reference sibling directories outside this repo (for example
  `../lib` and `../processexecutor`).

Driver
- Open `gswdrv/geswall.sln` and build, or run `gswdrv/ddkbuild.cmd` directly
  (run it without args to see supported targets).

User-mode components
- `gswserv/gswserv.sln` (service).
- `gswui/gswui.sln` (tray UI).
- `gswmmc/gswmmc.sln` (MMC snap-in).
- `gswshext/gswshext.msvc71.sln` (shell extension).
- `gswgp/gswgp.sln` (Group Policy extension).
