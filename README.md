# Forge Defcon

PC scanner for detecting cheats, prohibited software, and DMA hardware. Built with WPF (.NET 9).

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![.NET](https://img.shields.io/badge/.NET-9.0-purple)
![License](https://img.shields.io/badge/license-MIT-green)

**[Releases](https://github.com/uixcherry/Forge.Defcon/releases)** — скачать `Forge.Defcon.exe` (Windows x64, self-contained, ~130 MB)

---

## Руководство для администраторов

### Общие рекомендации по выявлению читеров

1. **Запускайте полное сканирование** — все 20 модулей дают полную картину.
2. **Обращайте внимание на Critical** — это прямые улики (процессы, драйверы, DMA, файлы).
3. **High** — косвенные признаки (история браузера, автозагрузка, исключения Defender).
4. **Cleanup Detector** — если сработал, читер мог затирать следы перед проверкой.
5. **Комбинация угроз** — несколько детекторов по одной теме почти всегда означают использование читов.

---

## Справочник детекторов

| Детектор | Что ищет | Severity |
|----------|----------|----------|
| **Process Scanner** | Cheat Engine, x64dbg, IDA, инжекторы, тренеры, PCILeech, HWID Spoofer | Critical |
| **Driver Scanner** | kdmapper, dbk64, capcom.sys, mhyprot, pcileech.sys | Critical |
| **DMA Scanner** | PCILeech, Screamer, FPGA (Xilinx, Altera, FT601), Thunderbolt | Critical |
| **File Scanner** | cheatengine.exe, pcileech.exe, .ct, aimbot, dma_cheat | Critical–High |
| **Registry Scanner** | Uninstall, UserAssist, BAM, отладчики | Critical–Medium |
| **Memory Scanner** | DLL читов в процессах (speedhack, aimbot, d3dhook) | Critical |
| **Device Scanner** | DMA USB (FT601, Xilinx), FPGA-адаптеры | Critical |
| **VM Scanner** | VMware, VirtualBox, Hyper-V, QEMU | Info–Medium |
| **Steam Account** | Steam-аккаунты, мультиакки | Info–Medium |
| **Cleanup Detector** | Prefetch очищен, Event Log стёрт, CCleaner | Critical |
| **Isolation Scanner** | Firewall/Defender/Secure Boot/UAC выключены | Medium |
| **Startup Scanner** | Автозагрузка читов (Run, Startup, Tasks) | High |
| **Network Scanner** | hosts блокирует античит, proxy/DNS | Critical–Medium |
| **Defender Exclusions** | Исключения для путей читов | Critical |
| **USB History** | Rubber Ducky, Bash Bunny, Teensy, Flipper | Critical |
| **Execution History** | Prefetch, AmCache, MuiCache — запуск читов | Critical |
| **Browser History** | UnknownCheats, MPGH, cheat engine | High |
| **HWID Spoofer** | AntiFakHWID, volumeid, spoofer | Critical |
| **Kernel Debug** | Test signing, отключена проверка подписи | High |
| **Game Cheats** | Файлы читов в папках игр | High |
| **Suspicious Services** | Сервисы kdmapper, spoofer, inject | High |

---

## Сборка и запуск

```bash
cd Forge.Defcon
dotnet restore
dotnet build
dotnet run
```

Требуется **Windows** и **.NET 9 SDK**.

### Публикация exe

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ../publish
```

---

## Структура проекта

```
├── Assets/           # Иконка
├── Converters/       # WPF конвертеры
├── Models/           # ThreatInfo, LogEntry, ScanResult
├── Services/         # 20 сканеров + ScanEngine
├── Themes/           # DarkTheme.xaml
├── ViewModels/       # MVVM
├── MainWindow.xaml
└── App.xaml
```

---

## Лицензия

MIT
