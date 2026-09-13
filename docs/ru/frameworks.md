# Примеры для фреймворков

В репозитории находятся запускаемые примеры, использующие общую реализацию
алгоритмов:

| Пример | Что демонстрирует |
|---|---|
| `examples/node` | Хеширование файла и отделённая CMS-подпись через PFX |
| `examples/react` | Хуки, выбор сертификата, подпись CryptoPro и проверка в JS |
| `examples/angularjs` | Dependency injection AngularJS с провайдером сертификатов |
| `examples/jquery` | Установка API провайдера в экземпляр jQuery |
| `examples/cryptopro-browser` | Страница без сборщика с общей IIFE-сборкой |

Команды запуска находятся в каталоге
[examples](https://github.com/krotos139/js-gostcrypto/tree/main/examples).

## React

```sh
npm install @gostcrypto/asn1 @gostcrypto/cms @gostcrypto/providers @gostcrypto/react react react-dom
```

Оберните приложение в `GostCryptoProvider`, затем используйте
`useCertificates` и `useGostSign` в клиентских компонентах. CryptoPro нельзя
инициализировать во время серверного рендеринга.

## Node.js

```sh
npm install @gostcrypto/hash @gostcrypto/node @gostcrypto/cms
```

Node.js может хешировать файлы, открывать PFX, использовать системное хранилище
CryptoPro в Windows или запускать ограниченный локальный мост для подписи.

## Angular и AngularJS

Для AngularJS есть `@gostcrypto/angularjs`. Современному Angular отдельный
адаптер не нужен: импортируйте ESM-пакеты в сервис и передайте
`CertificateProvider` через dependency injection Angular.

## jQuery и другие приложения

`@gostcrypto/jquery` добавляет операции провайдера в выбранный экземпляр
jQuery. Vanilla JavaScript, Vue, Svelte, Solid и другие сборщики могут напрямую
использовать те же ESM-пакеты и интерфейс `CertificateProvider`.
