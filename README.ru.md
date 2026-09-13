# gostcrypto-js

[English](README.md) | [Русский](README.ru.md)

TypeScript-порт библиотеки
[go-gostcrypto](https://github.com/krotos139/go-gostcrypto). Результат сборки —
обычный JavaScript с декларациями TypeScript, пригодный для Node.js, браузеров,
React, AngularJS, jQuery и современных сборщиков.

Запланированный объём портирования завершён. В тестах сохранены векторы RFC и
ГОСТ из Go-проекта, а в реализацию перенесены применимые к JavaScript табличные,
блочные и эллиптические оптимизации Go-версии. Подробности приведены в
[аудите оптимизаций](docs/OPTIMIZATIONS.md).

> Проект не является сертифицированным средством криптографической защиты.
> Браузерный код не может напрямую читать закрытые ключи из системного
> хранилища или USB-токена: операция подписи делегируется CryptoPro либо
> аутентифицированному локальному провайдеру.

## Связанные проекты

- [gostcryptkit](https://github.com/krotos139/gostcryptkit) — связанный набор
  криптографических инструментов;
- [go-gostcrypto](https://github.com/krotos139/go-gostcrypto) — Go-реализация,
  из которой портированы алгоритмы и тестовые векторы.

## Реализованные алгоритмы и форматы

| Стандарт | Реализация |
|---|---|
| ГОСТ Р 34.12-2015 | Блочные шифры Магма и Кузнечик |
| ГОСТ Р 34.13-2015 | ECB, CTR, CBC, OFB, CFB, padding и OMAC |
| ГОСТ Р 34.11-2012 | Потоковые Стрибог-256 и Стрибог-512 |
| ГОСТ Р 34.10-2012 | Кривые ТК26, подпись, кодеки ключей и VKO-2012 |
| RFC 7836 / Р 1323565.1.017-2018 | KDF, KDF_TREE, CTR-ACPKM, ACPKM-Master, KExp15/KImp15 |
| RFC 9058 / RFC 9059 | Аутентифицированное шифрование MGM |
| Устаревшие стандарты | ГОСТ 28147-89, ГОСТ Р 34.11-94, CryptoPro key wrap |
| PKI и контейнеры | DER/ASN.1, PKIX, PKCS#8/#10/#12, сертификаты, CRL, CMS, CAdES-BES/T, RFC 3161, RFC 4490 |
| Доступ к сертификатам | PFX, браузерный плагин CryptoPro, Windows CAdESCOM, аутентифицированный HTTP-мост |

Основные пакеты рабочего пространства:

| Пакет                                                                         | Назначение                                               |
| ----------------------------------------------------------------------------- | -------------------------------------------------------- |
| `@gostcrypto/gostcrypto`                                                      | Общие сборки ESM, CommonJS, browser ESM и browser IIFE   |
| `@gostcrypto/hash`, `@gostcrypto/ciphers`, `@gostcrypto/modes`                | Низкоуровневые примитивы                                 |
| `@gostcrypto/signature`, `@gostcrypto/vko`                                    | Подпись и согласование ключей                            |
| `@gostcrypto/asn1`, `@gostcrypto/pkcs8`, `@gostcrypto/pfx`, `@gostcrypto/cms` | Ключи, сертификаты, контейнеры и документы               |
| `@gostcrypto/providers`                                                       | Провайдеры PFX, браузерного плагина и локального моста   |
| `@gostcrypto/node`                                                            | PFX в Node.js, системное хранилище CryptoPro и CLI моста |
| `@gostcrypto/react`, `@gostcrypto/angularjs`, `@gostcrypto/jquery`            | Необязательные адаптеры фреймворков                      |

## Установка

Общий пакет с алгоритмами и форматами устанавливается так:

```sh
npm install @gostcrypto/gostcrypto
```

ES modules и сборщики:

```js
import { hash, cms, providers } from "@gostcrypto/gostcrypto";

const digest = hash.streebog256(new TextEncoder().encode("hello"));
```

CommonJS в Node.js:

```js
const { hash, cms } = require("@gostcrypto/gostcrypto");
```

Обычная браузерная страница может подключить файл
`dist/gostcrypto.min.js` и использовать глобальный объект `GostCrypto`.

## React, Node.js, AngularJS и jQuery

Дополнительные пакеты или манифесты не требуются. У каждого пакета уже есть
карта `exports`, декларации `.d.ts`, ограниченный список публикуемых файлов и
метаданные для tree shaking. React, AngularJS и jQuery оформлены как peer
dependencies адаптеров, поэтому приложение само выбирает версию фреймворка.

Достаточно установить нужный адаптер:

```sh
# React
npm install @gostcrypto/gostcrypto @gostcrypto/providers @gostcrypto/react

# Node.js и исполняемый файл локального моста
npm install @gostcrypto/gostcrypto @gostcrypto/node

# AngularJS или jQuery
npm install @gostcrypto/gostcrypto @gostcrypto/angularjs
npm install @gostcrypto/gostcrypto @gostcrypto/jquery
```

Пример для React:

```jsx
import {
  GostCryptoProvider,
  useCertificates,
  useGostSign,
} from "@gostcrypto/react";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const provider = createCryptoProBrowserProvider();

export function App() {
  return (
    <GostCryptoProvider provider={provider}>
      <Signer />
    </GostCryptoProvider>
  );
}

function Signer() {
  const { certificates } = useCertificates();
  const sign = useGostSign();
  // Вызывайте sign(certificateId, Uint8Array, options) из обработчика события.
  return <div>Сертификатов: {certificates.length}</div>;
}
```

Node.js умеет напрямую открывать PFX:

```js
import { openPfxFile } from "@gostcrypto/node";

const provider = await openPfxFile("signing-key.pfx", "password");
```

В Node.js 18 для операций, генерирующих случайные ключи, nonce, salt или ключи
шифрования содержимого, нужен параметр
`NODE_OPTIONS=--experimental-global-webcrypto`. В Node.js 20 и новее необходимый
генератор Web Crypto доступен по умолчанию.

Подробности есть в [руководстве по средам и фреймворкам](docs/INTEGRATIONS.md).

## Сертификаты браузера и USB-токены

При наличии официального расширения CryptoPro и загруженного
`cadesplugin_api.js` библиотека может показать сертификаты, проверить цепочку
и попросить CSP или USB-токен создать CAdES-подпись. Закрытый ключ при этом не
попадает в память JavaScript.

```js
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const provider = createCryptoProBrowserProvider();
const certificates = await provider.listCertificates();
const signature = await provider.sign(certificates[0].id, documentBytes, {
  algorithm: "gost3410-2012-256",
  detached: true,
  checkCertificate: true,
});
```

Интерактивная страница запускается командой
`npm run test:browser:cryptopro`. Она показывает сертификаты и позволяет
создать и проверить подпись выбранным сертификатом. Если прямой доступ через
плагин невозможен, используйте аутентифицированный Node.js-мост из
[руководства по нативному мосту](docs/NATIVE_BRIDGE.md).

## Производительность

Измерено 13 сентября 2026 года в Node.js 22.14.0 для Windows x64 на Intel Core
i7-9700K 3.60 ГГц. Указана медиана пяти запусков. Все реализации получили
одинаковые входы и кривые; перед замером сверялись хэши, зашифрованные блоки,
открытые ключи, нормализованные детерминированные подписи и их проверка.

| Операция | gostcrypto-js | @li0ard/gost 0.2.4 | node-gost-crypto 1.0.2 |
|---|---:|---:|---:|
| Стрибог-256, 8 КиБ | **11.48 MB/s** | 0.24 MB/s | 9.70 MB/s |
| Стрибог-512, 8 КиБ | 10.76 MB/s | 0.20 MB/s | **10.86 MB/s** |
| Кузнечик, один блок | **1.0 мкс** | 84.2 мкс | 81.8 мкс¹ |
| Магма, один блок | **181 нс** | 2.4 мкс | 1.5 мкс¹ |
| Развёртка ключа Кузнечика | 718.8 мкс | 386.0 мкс | **83.7 мкс¹** |
| Подпись, 256 бит | **511.9 мкс** | 1.30 мс | 1.29 мс² |
| Проверка, 256 бит | **4.77 мс** | 6.54 мс | 9.92 мс² |
| Подпись, 512 бит | **1.06 мс** | 3.79 мс | 2.05 мс² |
| Проверка, 512 бит | **19.71 мс** | 26.26 мс | 51.01 мс² |

¹ Публичный API шифра `node-gost-crypto` разворачивает ключ для каждого блока.
² Его публичный API подписи дополнительно хэширует 32-байтовый вход.

Бенчмарк только текущей реализации:

```sh
npm run benchmark
```

Воспроизводимое сравнение с `@li0ard/gost` и `node-gost-crypto`:

```sh
npm run benchmark:compare
```

Сравнение включает все операции из основной сравнительной таблицы
`go-gostcrypto`. Результаты, методика, оговорки по API, разбор оптимизации
Стрибога и ссылки на другие JS-реализации приведены в
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Разработка и CI

```sh
npm ci
npm run validate:packages
npm test
npm pack --workspaces --dry-run
```

GitHub Actions тестирует Node.js 18, 20 и 22 в Linux, выполняет smoke-тест в
Windows, проверяет манифесты и npm-архивы и запускает сравнительный бенчмарк как
проверку корректности. Теги `v*` обрабатываются отдельным workflow публикации
в npm с provenance.

## Безопасность

Операции JavaScript `BigInt` и JIT-компиляция не являются constant-time, а
индексы lookup-таблиц зависят от обрабатываемых данных. Если модель угроз
включает враждебный локальный код, операции с закрытым ключом должны оставаться
в проверенном CSP, аппаратном токене или нативном агенте; `CertificateProvider`
используется только как граница.

На Windows команда `npm run interop:cryptopro` сравнивает детерминированные
результаты Стрибог-256/512 и ГОСТ Р 34.11-94 с установленным `csptest.exe`.

## Лицензия

MIT. Полный текст приведён в файле [LICENSE](LICENSE).

Copyright (c) 2026 IURII IAKOVLEV
