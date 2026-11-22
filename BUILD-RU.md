# Сборка Windows x64

На Windows требуются Git, Go 1.27 или новее и .NET Framework 4.8. Для окна используется компилятор C# из .NET Framework. Visual Studio не требуется.

В VS Code откройте этот каталог и нажмите **Ctrl+Shift+B**. Откроется окно сборки. Для первого запуска включите загрузку зависимостей, затем нажмите «Собрать ZIP».

Те же действия через PowerShell:

    powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-Windows.ps1 -RestoreDependencies

Для повторной сборки используйте команду без **-RestoreDependencies**. Готовый ZIP и SHA256 появятся в папке **dist**. Внутри ZIP есть **BUILD-INFO.json** с версией и идентификатором исходников.

## Конфигурация сервиса

В публичном исходном коде используются демонстрационный адрес панели и пустой список приложений VK. Эти значения позволяют собрать проект и запустить интерфейс. Для подключения к вашему сервису передайте пути к локальным файлам через **-PanelBootstrap** и **-VKAppConfig**. Можно также поместить файлы **panel-bootstrap.json** и **vk-apps.json** в папку **.private** проекта. Папка исключена из Git.

Форму файла панели показывает **native/CombinedXray/internal/desktop/bootstrap.json**. Для VK требуется массив объектов с полями **clientId** и **clientSecret** от владельца сервиса. Локальная конфигурация подставляется при сборке сетевого EXE. Проверяйте адрес сервиса и разрешение на распространение конфигурации перед передачей своего ZIP.

Для тестов на Windows из каталога проекта:

    go -C native/CombinedXray test -mod=readonly ./internal/desktop

Системные тесты Wintun включаются отдельно переменной TNDTUN_SYSTEM_TEST=1. Они используют тестовые адаптеры и отдельные маршруты /32. Для них требуются права администратора и wintun.dll рядом с тестовыми исполняемыми файлами.

## Публикация в GitHub Releases

Установите GitHub CLI и выполните `gh auth login` под аккаунтом **Stepan-Gribov**. Для нового релиза укажите `version` и `fileVersion` в `project.json`, отправьте коммит в `main`, затем соберите и проверьте ZIP из этого коммита.

В VS Code откройте **Terminal → Run Task → TnDtun: опубликовать готовый ZIP в GitHub Releases**. Задача берёт ZIP и файл `.sha256` из `dist`. Из PowerShell можно указать путь к готовому ZIP и проверить публикацию без записи флагом `-WhatIf`.

    powershell -NoProfile -ExecutionPolicy Bypass -File .\Publish-Windows.ps1

ZIP и `SHA256SUMS.txt` публикуются в [закрытых Releases сборок](https://github.com/Stepan-Gribov/vpn-builds/releases). После проверки скачанного ZIP появляется страница версии с инструкцией и ссылкой на загрузку в [Releases исходников Windows](https://github.com/Stepan-Gribov/vpn-windows/releases). Для изменившегося ZIP используйте новый номер версии.
