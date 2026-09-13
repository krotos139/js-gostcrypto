# Сертификаты и USB-токены

Стандартный WebCrypto не позволяет браузерному JavaScript читать произвольные
закрытые ключи из системного хранилища или USB-токена. Библиотека предоставляет
три границы:

1. `createCryptoProBrowserProvider()` обращается к официальному расширению
   CryptoPro через `cadesplugin_api.js`.
2. `createHttpCertificateProvider()` вызывает аутентифицированный нативный или
   удалённый мост подписи.
3. `PfxCertificateProvider` обрабатывает явно переданный PFX внутри процесса
   JavaScript.

При использовании CryptoPro закрытый ключ остаётся в CSP или токене:

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

Браузерное приложение следует отдавать с `localhost` или по HTTPS. Официальный
API CryptoPro должен быть загружен до создания провайдера. Проверка доверия к
сертификату и математическая проверка CMS-подписи — разные операции, приложению
нужны обе.

Интерактивный тест без сборщика запускается командой:

```sh
npm run test:browser:cryptopro
```

Модель угроз и настройки локального агента описаны в
[руководстве по нативному мосту](../NATIVE_BRIDGE.md).
