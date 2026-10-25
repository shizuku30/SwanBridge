# Application Icon

The user supplied `SwanBridge.png` as the application artwork on 2026-10-24.
The original PNG is stored unchanged, including its alpha channel.

- Dimensions: 512 x 512 pixels, RGBA
- SHA256: `D5DEF1F301EDCBA42EC417EFD73D07C2131337090A9D7DFCC8F5381477FD8490`

`scripts/Generate-IconAssets.ps1` reads only this repository-relative PNG.
It generates the MSIX scale and target-size assets, transparent unplated
variants, and a multi-size ICO for the foreground and host executables.
The build does not extract Windows system artwork or use the original
attachment location. No third-party image dependency is required.

The PNG replaces the previously selected Windows Network shell icon.
The repository owner confirmed on 2026-10-25 that they have redistribution rights
and authorize publication under GPL-2.0-or-later, the project's source license.
Ownership remains with the respective rights holder. See `LICENSING.md`.
