# CLAUDE.md - PivotPHP Security

Este arquivo orienta o trabalho no pacote **pivotphp/security**.

## Visão geral

Middlewares PSR-15 de segurança para o PivotPHP e qualquer pipeline PSR-15. Dependências
obrigatórias: apenas interfaces PSR (`psr/http-message`, `psr/http-factory`,
`psr/http-server-*`). Cada adapter depende da sua biblioteca, declarada em `suggest` e com versão
mínima em `conflict`.

| Componente | Implementação |
|---|---|
| `Cors` | própria (nenhuma biblioteca PSR-7 madura e ativa compatível com PSR-7 2.0) |
| `Proxy` | própria (só existe acoplado ao HttpFoundation) |
| `Headers` | adapter de `bepsvpt/secure-headers` |
| `Csrf` | adapter de `yiisoft/csrf` |
| `Jwt` | adapter de `firebase/php-jwt` |
| `RateLimit` | adapter de `symfony/rate-limiter` (`RateLimiterFactory`; a interface só existe a partir da 7.3) |

## Comandos

```bash
composer test           # PHPUnit
composer phpstan        # PHPStan nível 9 (src + tests)
composer cs:check       # PSR-12
composer quality:check  # phpstan + cs:check + test
```

## Regras de design

- **Um middleware por preocupação**; config em objeto imutável (`readonly`, PHP 8.1 — não usar
  `readonly class`, que exige 8.2), validado no construtor com `InvalidConfigurationException`.
- **Fail closed**: falha de verificação devolve resposta (`401/403/429`) criada pela
  `ResponseFactoryInterface` injetada; nunca chama o handler. Não lançar exceção para o cliente.
- **Não implementar criptografia**: JWT, tokens CSRF e contagem atômica ficam nas bibliotecas.
- **Sem estado estático entre requisições** (por isso nonces de CSP não são suportados; o
  `JWT::$leeway` do firebase é restaurado em `finally`).
- Matriz de CI: PHP 8.1 com dependências mínimas; 8.3 e 8.4 com máximas.
