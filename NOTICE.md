# Source and attribution notice

This repository combines a project-owned scanning pipeline with algorithms, rule
sets and data informed by the sources below. Each project is credited with its origin;
no upstream source code is copied into this repository.

| Component or data | Upstream / origin | Local treatment |
|---|---|---|
| Directory discovery | [dirsearch](https://github.com/maurosoria/dirsearch) | Pure-Python compatible core; no component-local venv or runtime clone |
| Fingerprint rules | [Finger](https://github.com/sangnigege/Finger)  | `finger.json` converted to package data; EHole binary is not shipped |
| 403 payload catalog | [nomore403](https://github.com/devploit/nomore403) and [403bypasser](https://github.com/yunemse48/403bypasser) | Payload snapshot in `assets/bypass403/payloads.json`; no runtime import or clone; MIT per upstream README |
| JS discovery | [JSFinder](https://github.com/Threezh1/JSFinder) | Rewritten under the shared HTTP/result contracts |
| Swagger/OpenAPI | [swagger-exp](https://github.com/lijiejie/swagger-exp) and [swagger-hack](https://github.com/jayus0821/swagger-hack) parsing and request-generation ideas | Parser/request generation only; no browser UI, ChromeDriver or Excel writer |
| Packer analysis | [Packer-Fuzzer](https://github.com/rtcatc/Packer-Fuzzer) | Core analysis is folded into the Python package; no SQLite/CWD stage bus, component venv, browser, or runtime clone |

SurfaceScope is an independent implementation: it does not copy source code from
the projects listed above. The references record the ideas, algorithms, asset formats
and rule sets that informed the work, and the upstream project names and links are
listed for attribution only.

The 403 payload snapshot is executed by the project-owned catalog/adapter, not by
importing upstream code. Its supported boundary is the unified `requests`
executor: raw absolute-URI requests, duplicate request headers, CL/TE
desynchronisation and HTTP/1.0 transport switching are intentionally not
emulated and are not claimed as implemented. The exact-path option preserves
percent-encoded path semantics while still using the shared executor, session,
budget, audit and redirect controls.
