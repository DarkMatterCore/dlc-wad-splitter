# dlc-wad-splitter

Splits full Wii DLC WAD packages into smaller WADs, suitable for DLC tools. Heavily based on [wad2bin](https://github.com/DarkMatterCore/wad2bin).

Usage:
--------------

```
dlc-wad-splitter v0.1 (c) DarkMatterCore.
Built: 17:41:19 Jul 14 2020.

Usage: dlc-wad-splitter <input WAD> <output dir> <content count per split DLC>

Paths must not exceed 259 characters. Relative paths are supported.
The input WAD package must hold a TMD with a valid signature, as well as all the contents referenced
in the content records section from the TMD. If a single content is missing or has a wrong hash, the
process will be stopped.
Furthermore, the total content count minus 1 must be a multiple of the provided content count.
Output split DLC WADs will hold content #0 + "content count" contents.
For more information, please visit: https://github.com/DarkMatterCore/dlc-wad-splitter.
```

Building instructions:
--------------

* **Windows** (should you really bother? 32-bit binaries are provided):
    1. A collection of Unix/Linux utilities such as `make`, `mkdir`, `rm`, `ar` and `cp`, as well as a `gnu11` standard compliant C compiler, are needed to build this project. There are a few ways to achieve this under Windows:
        * Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/download) and [devkitPro + MSYS2](https://devkitpro.org/wiki/Getting_Started#Windows), or...
        * Install [MinGW + MSYS](http://www.mingw.org/wiki/Getting_Started), or...
        * (Untested) Under Windows 10:
            * Install the [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/install-win10) distribution of your preference (I'll assume you chose Ubuntu).
            * Install the `gcc` package by using the `sudo apt update` and `sudo apt install gcc` commands.
            * Modify the Makefiles to use `wsl.exe` before each Unix command call.
        * Regardless of the option you end up choosing, please make sure your `PATH` environment variable has been properly updated!
    2. Create a copy of `config.mk.template` in the same directory and rename it to `config.mk`.
    3. Build using the `make` command.

* **Unix-like OS (Linux / MacOS)**:
    1. Install your preferred C compiler compatible with the `gnu11` standard using your OS's package manager (e.g. `apt`, `pacman`, `brew`, etc.).
    2. Create a copy of `config.mk.template` in the same directory and rename it to `config.mk`. Open it with a text editor.
    3. Update the `CC` variable to make it point to your installed C compiler (leaving `gcc` is usually fine), and wipe the value from the `EXE_EXT` variable.
    4. Build using the `make` command.

Supported DLCs:
--------------

Not all DLCs can be splitted - this is because not all games are capable of loading only a subset of the content files from their DLCs. For this purpose, dlc-wad-splitter holds a hardcoded DLC title ID list, in order to avoid splitting a DLC WAD that simply won't work.

Only the following DLCs are supported:

* Rock Band 2 (`00010000-535A41xx`) (`SZAx`):
    * `00010005-735A41xx` (`sZAx`).
    * `00010005-735A42xx` (`sZBx`).
    * `00010005-735A43xx` (`sZCx`).
    * `00010005-735A44xx` (`sZDx`).
    * `00010005-735A45xx` (`sZEx`).
    * `00010005-735A46xx` (`sZFx`).

* The Beatles: Rock Band (`00010000-52394Axx`) (`R9Jx`):
    * `00010005-72394Axx` (`r9Jx`).

* Rock Band 3 (`00010000-535A42xx`) (`SZBx`):
    * `00010005-735A4Axx` (`sZJx`).
    * `00010005-735A4Bxx` (`sZKx`).
    * `00010005-735A4Cxx` (`sZLx`).
    * `00010005-735A4Dxx` (`sZMx`).

* Guitar Hero: World Tour (`00010000-535841xx`) (`SXAx`):
    * `00010005-735841xx` (`sXAx`).
    * `00010005-73594Fxx` (`sYOx`).

* Guitar Hero 5 (`00010000-535845xx`) (`SXEx`):
    * `00010005-735845xx` (`sXEx`).
    * `00010005-735846xx` (`sXFx`).
    * `00010005-735847xx` (`sXGx`).
    * `00010005-735848xx` (`sXHx`).

* Guitar Hero: Warriors of Rock (`00010000-535849xx`) (`SXIx`):
    * `00010005-735849xx` (`sXIx`).

* Just Dance 2 (`00010000-534432xx`) (`SD2x`):
    * `00010005-734432xx` (`sD2x`).

* Just Dance 3 (`00010000-534A44xx`) (`SJDx`):
    * `00010005-734A44xx` (`sJDx`).

* Just Dance 4 (`00010000-534A58xx`) (`SJXx`):
    * `00010005-734A58xx` (`sJXx`).

* Just Dance 2014 (`00010000-534A4Fxx`) (`SJOx`):
    * `00010005-734A4Fxx` (`sJOx`).

* Just Dance 2015 (`00010000-534533xx`) (`SE3x`):
    * `00010005-734533xx` (`sE3x`).

Any DLCs not appearing on this list will return an error if used as the input WAD package for the program. If you come across a DLC that can be splitted and it doesn't appear on this list, please contact me or open an issue and I'll gladly add it.

Dependencies:
--------------

* [ninty-233](https://github.com/jbop1626/ninty-233) (licensed under GPLv3 or later) is used for ECDSA signature verification.
* [mbedtls](https://tls.mbed.org) (licensed under Apache 2.0) is used for hash calculations, AES-CBC crypto operations and RSA signature verification.

License:
--------------

dlc-wad-splitter is licensed under GPLv3 or (at your option) any later version.

Changelog:
--------------

**v0.1:**

Initial release.
