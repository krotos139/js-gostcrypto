# Начало работы

`gostcrypto-js` предоставляет алгоритмы ГОСТ, форматы ключей и сертификатов,
CMS и адаптеры провайдеров в отдельных npm-пакетах `@gostcrypto/*`. Одинаковые
JavaScript-реализации и TypeScript-декларации работают в Node.js, современных
браузерах и популярных сборщиках.

## Установка

Если приложению нужно несколько возможностей, установите общий пакет:

```sh
npm install @gostcrypto/gostcrypto
```

```js
import { hash } from "@gostcrypto/gostcrypto";

const data = new TextEncoder().encode("hello");
const digest = hash.streebog256(data);
```

Пакеты `@gostcrypto/hash`, `@gostcrypto/ciphers`, `@gostcrypto/cms` и другие
позволяют подключать только нужные API.

## Поддерживаемые среды

- Все пакеты содержат ESM-сборку.
- Общий пакет также предоставляет CommonJS и браузерные сборки.
- Во всех пакетах есть TypeScript-декларации и карта `exports`.
- React, AngularJS и jQuery подключаются необязательными адаптерами.

Готовые проекты описаны в разделе [Примеры для фреймворков](frameworks.md).
Перед реализацией подписи прочитайте раздел
[Сертификаты и USB-токены](certificates.md).

## Разработка

```sh
npm ci
npm test
npm run validate:examples
```

Алгоритмы и тестовые векторы перенесены из
[go-gostcrypto](https://github.com/krotos139/go-gostcrypto). Подробности есть в
[отчёте о производительности](../BENCHMARKS.md) и
[аудите оптимизаций](../OPTIMIZATIONS.md).
