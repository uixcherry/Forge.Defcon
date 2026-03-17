# Инструкция по созданию Release

## 1. Сборка exe

```powershell
cd Forge.Defcon
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ../publish
```

Готовый `Forge.Defcon.exe` (~130 MB) будет в папке `publish/`.

## 2. GitHub — первый пуш

1. Создайте репозиторий на GitHub (например `Forge.Defcon`).
2. Добавьте remote и запушьте:

```bash
git remote add origin https://github.com/YOUR_USERNAME/Forge.Defcon.git
git branch -M main
git push -u origin main
```

## 3. GitHub Release

1. **Releases** → **Create a new release**
2. Tag: `v1.0.0` (создать новый)
3. Title: `v1.0.0`
4. Описание: краткое описание (можно скопировать из README)
5. **Attach binaries** → загрузите `Forge.Defcon.exe` из `publish/`
6. **Publish release**

## 4. Требования для пользователей

- **Windows 10/11** (x64)
- **.NET 9** не требуется — exe self-contained
