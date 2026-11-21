# Сборка платформ

Ядро — Cargo workspace в корне репозитория. Профиль криптографии один: `ed25519+sha256-merkle+x25519-chacha20poly1305+did:key`.

## Linux

На NAS (`192.168.1.114`, rustc 1.97.0):

```bash
cargo test --workspace
cargo run -p clavis-holder-linux
cargo run -p clavis-verifier
cargo run -p clavis-issuer
cargo run -p clavis-registry
```

Приёмка презентации:

```bash
cargo test -p clavis-protocol --test presentation_release -- --exact freshness_one_field_encrypted_to_verifier
```

## Android

Телефон на NAS: `R5CT92MDXRH`, модель `SM_S908E`, состояние `device`. Установка и экран только через `android-device-queue`, проект `CLAVIS`. ADB не является каналом протокола.

Сборка идёт на Beast (`192.168.1.112`, user `beast`, `x86_64`), когда ping и SSH отвечают. Там rustc 1.100.0 в домашнем каталоге пользователя, JDK 17, `ANDROID_HOME=/home/beast/Android/Sdk`, NDK `27.2.12479018`, symlink `/usr/lib/jvm/java-17-openjdk-arm64` есть. Каталог исходников на Beast: `/home/beast/src/clavis`. Gradle 8.7 ставится в `/home/beast/sdks/gradle-8.7`, рядом с чужими SDK, не вместо них. Дерево `/home/beast/vocolibri_web_player/mobile/flutter` не трогать, если оно появится.

```bash
scripts/build-android.sh
scripts/install-phone.sh
```

Оболочка — Java. Протокольный крейт не содержит имён Android API. Библиотека `libclavis_ffi.so` для `arm64-v8a`, `minSdk` 26, `compileSdk` 35.

Если Beast не отвечает на ping и SSH, сборка остаётся на NAS. Пока на NAS нет Android SDK, `scripts/build-android.sh` на этом запасном пути завершается с ошибкой и не выдумывает третью машину.

## Windows

Крейт `clavis-holder-windows` собирается на NAS тем же `cargo test -p clavis-holder-windows`. Объявленный хост MyNUC (`192.168.1.108`, user `akona`) ответил по SSH: `MYNUC`, Microsoft Windows 10.0.26300. Двоичный файл держателя на MyNUC этой сборкой не выпускался.

## iOS

В каталоге объявлений `/home/pi/Documents/shared/hosts` есть `beast`, `MyNUC` и `NAS`. Mac mini там нет. Адрес не назначается. Команда сборки, когда в объявлении появится macOS-хост:

```bash
xcodebuild -project apps/ios/ClavisHolder.xcodeproj -scheme ClavisHolder -destination 'generic/platform=iOS' build
```

Эта команда не запускалась. Успех сборки iOS не заявлен. Символ ядра для оболочки: `clavis_profile(uint8_t *out, size_t cap) -> int32_t`.
