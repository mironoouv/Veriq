# Известные ограничения

- [PR #2](https://github.com/mironoouv/Veriq/pull/2). Worker рассчитан на короткую доверенную SQL-пробу. Lease и восстановление длительных задач описаны как предложение.
- [PR #2](https://github.com/mironoouv/Veriq/pull/2). Сроки хранения и очистка `background_jobs` ждут согласования. Автоматической очистки нет.
- [PR #2](https://github.com/mironoouv/Veriq/pull/2). Starlette предупреждает об устаревающей интеграции `httpx` в тестах. Браузерный E2E запланирован отдельно.
