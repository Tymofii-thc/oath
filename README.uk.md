<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="verifier/assets/logo-white.svg">
    <img src="verifier/assets/logo-black.svg" alt="oath." height="64">
  </picture>
</p>

[English](README.md) · **Українська**

*Не деплой того, чого не збирав пайплайн.*

> Версія, подана на хакатон, має тег [`hackathon-submission`](https://github.com/Tymofii-thc/oath/tree/hackathon-submission). У `main` є пізніші виправлення безпеки (див. [THREAT-MODEL.md](THREAT-MODEL.md)).

Інструмент, який не дає запустити в проді образ, що не збирав ваш пайплайн.

**Проблема.** Підмінений образ у реєстрі, ручний `docker push` у обхід CI, скомпрометований токен: ніхто не помітить, що в проді працює не те, що зібрали. Це supply chain атака.

**Рішення.** Кожна збірка записує в Solana незмінний запис `коміт → digest → час` (стандартна Memo-програма, власного смарт-контракту нема). Перед деплоєм `oath verify` звіряє digest образу з цими записами і **зупиняє деплой**, якщо запису нема.

```
build ──► image digest ──► Solana Memo tx (підпис CI-ключа)
                                  │
deploy ──► docker pull ──► oath verify ──► ✔ exit 0  → деплой іде
                                         ✘ exit 1  → деплой зупинено
```

**Встановлення:** `npm install -g oath-verify` дає команду `oath`. Або без встановлення: додай `npx --yes oath-verify` перед будь-якою командою нижче (зручно в CI, тоді фіксуй версію: `npx --yes oath-verify@0.3.2`). У клоні `node bin/oath.mjs` робить те саме. `oath` нижче означає будь-який із цих способів.

## Підключення за 3 кроки

**1. Ключ CI** (один раз, приблизно хвилина):
```bash
npx --yes oath-verify init      # або: node bin/oath.mjs init  у клоні
```
`oath init` створює ключ у `.oath/ci-key.json` (секрет не друкується, а `.oath/` потрапляє в `.gitignore`), просить у devnet-faucet SOL, а якщо публічний faucet відмовив (так буває часто), друкує посилання і **чекає, поки ти поповниш ключ**. Потім друкує, що саме додати в репозиторій: секрет `SOLANA_SECRET_KEY`, змінну `OATH_SIGNER` і два кроки workflow нижче. Якщо встановлено GitHub CLI і ти залогінений, `oath init --set-github` додасть секрет і змінну сам (перевірено зі справжнім `gh` на тимчасовому приватному репозиторії).

**2. Запис після збірки** (у вашому workflow):
```yaml
- uses: Tymofii-thc/oath@main
  with:
    image: ghcr.io/${{ github.repository }}
    digest: ${{ steps.build.outputs.digest }}
    secret-key: ${{ secrets.SOLANA_SECRET_KEY }}
```

**3. Перевірка перед деплоєм** (без npx і прапорців):
```yaml
- uses: Tymofii-thc/oath/verify@main
  with:
    signer: ${{ vars.OATH_SIGNER }}
    image: ghcr.io/${{ github.repository }}:latest
```
Action сам тягне образ і валить job (код 1), якщо для digest нема запису. Необов'язкові входи: `network`, `rpc`, `quorum`, `max-age`, `attest`, або `digest` замість `image`.

Повний мінімальний workflow (близько 40 рядків): [`examples/github-minimal.yml`](examples/github-minimal.yml). Додатковий захист поверх нього (походження збірки SLSA, потрібне для `--attest`, SBOM і скан Trivy) є в [`deploy.yml`](.github/workflows/deploy.yml) цього репозиторію. Покроковий гайд для тестування: [TESTING.md](TESTING.md).

## CLI
```bash
node bin/oath.mjs verify --signer <pubkey> --digest sha256:…
node bin/oath.mjs verify --signer <pubkey> --image ghcr.io/me/app:latest
node bin/oath.mjs verify --signer <pubkey> --container prod      # образ, що ЗАРАЗ працює
node bin/oath.mjs anchor --image ghcr.io/me/app:latest           # запис збірки з будь-якого CI (SOLANA_SECRET_KEY; digest бере з реєстру, docker не потрібен)
```
`verify --image repo@sha256:…` не потребує ні docker, ні звернення до реєстру. Якщо образу немає локально, digest тега береться з реєстру (приватні: `OATH_REGISTRY_AUTH`). Приклади для CI: [`examples/github-minimal.yml`](examples/github-minimal.yml) і [`examples/azure-pipelines.yml`](examples/azure-pipelines.yml) (Azure не перевірено на живому pipeline).
Коди виходу: `0` перевірено, `1` не перевірено, `2` помилка (мережа, аргументи). Для мейннету додай `--rpc <url>` або змінну `SOLANA_RPC` (і те саме для кроку 2 через вхід `rpc`).

`verifier/index.html` це та сама перевірка у браузері, для демо й для людей, які не лізуть у термінал. Живий: https://tymofii-thc.github.io/oath/

## Захист кластера (Kubernetes admission webhook)
Перевірка в CI-кроці не зупинить того, хто робить `kubectl apply` в обхід пайплайну. Тому є webhook, який стоїть у самому кластері:

```bash
OATH_SIGNER=<public key> OATH_NETWORK=mainnet deploy/install.sh   # генерує TLS, ставить webhook у namespace oath-system
kubectl run t --image=nginx        # → denied: no pipeline build anchored by the trusted signer(s)
```
- Для кожного нового Pod бере всі образи (`initContainers`, `containers`, `ephemeralContainers`), резолвить тег у digest через реєстр і шукає запис у Solana. Нема запису → Pod не створюється (в тому числі зі створених Deployment/Job).
- **Підмінює тег на перевірений digest** (`app:latest` → `app@sha256:…`), тож кубелет витягне саме те, що перевірено; тег між перевіркою і pull змінити не вдасться.
- **Fail closed:** недоступний реєстр, RPC чи сам webhook = Pod не проходить (`failurePolicy: Fail`). Виняток: `kube-system`, `kube-public`, `kube-node-lease` і namespace `oath-system` (щоб не заблокувати кластер).
- **Helm замість `install.sh`:** `helm install oath oci://ghcr.io/tymofii-thc/charts/oath --version 0.2.0 -n oath-system --create-namespace --set signer=<pubkey>` (значення: `network`, `rpc` / `rpcSecret`, `mode`, `failurePolicy`, `quorum`, `attestRepo`, `staleOkHours`, `registryAuth`, `auditSchedule`; TLS генерує Helm і не міняє при оновленні). Перевірено в kind: встановлення, відмова, оновлення з `mode=audit`, CronJob аудиту, видалення. Після `helm install` Service може відповідати з затримкою в кілька секунд.
- `OATH_MODE=audit` дозволяє все, але повертає попередження: зручно для першого впровадження.
- `OATH_FAILURE_POLICY=Ignore deploy/install.sh` міняє `failurePolicy` на `Ignore` (доступність важливіша за блокування; тоді користуйся `oath audit`). Webhook працює у 2 репліках із PodDisruptionBudget.
- Приватні реєстри: `OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}'` (перевірено на реєстрі з паролем і на моку з Bearer-токеном; кубелет усе одно потребує власних `imagePullSecrets`).
- Перевірено в реальному кластері (kind): `test/e2e-kind.sh` (допуск, pin, відмова, блокування Deployment, fail-closed при вимкненому webhook).

## Pod-и, що вже працюють
Webhook перевіряє лише нові Pod-и. Для вже запущених:
```bash
oath audit --signer <pubkey> --network mainnet [--skip-namespaces kube-system,…] [--file pods.json]
```
Бере всі контейнери поточного kube-контексту (`kubectl get pods -A -o json`, реальні digest з `imageID`), звіряє із записами, виходить з кодом 1, якщо є непідтверджені. Перевірено в kind: pod-и, створені до webhook, знаходяться (`alpine` VERIFIED, `nginx` NOT VERIFIED).

## Атестація збірки (SLSA provenance)
Запис у Solana доводить «підписант зафіксував digest», а не «збірка була чесною». Тому CI додатково випускає атестацію походження збірки через GitHub/Sigstore (keyless, без довгоживучого ключа), і `oath verify` може її вимагати:
```bash
oath verify --signer <pubkey> --image ghcr.io/me/app:latest --attest me/app
```
Перевіряється: криптографічний підпис і запис у журналі прозорості Sigstore (бібліотека `sigstore`, ланцюжок Fulcio), що підписала саме GitHub Actions репозиторію `me/app` (workflow-ідентичність), і що підписане твердження стосується саме цього digest та образу. Немає атестації, чужий репозиторій, інший digest або помилка API дають `NOT VERIFIED`/код 2, а не «ок». Для webhook: `OATH_ATTEST_REPO=me/app deploy/install.sh`. Перевірено на справжній атестації нашого CI (і негативні кейси: чужий репозиторій, образ без атестації).

## Кворум підписантів (захист від вкраденого ключа CI)
Один ключ у секретах CI це єдина точка відмови. Тому образ можна вважати підтвердженим, лише якщо **N різних ключів** зробили запис про його digest:
```bash
# створи ключ затверджувача (тримай його ПОЗА CI; команда друкує публічний ключ і наступні кроки, і не пропонує додавати його в GitHub):
oath init --approver
# CI-ключ записує автоматично; людина-затверджувач записує зі свого ключа (ноутбук, окремий пристрій):
SOLANA_SECRET_KEY="$(cat approver.json)" node scripts/anchor.mjs --image ghcr.io/me/app --digest sha256:… --commit <sha>
# перед деплоєм:
oath verify --signer <ciKey>,<approverKey> --quorum 2 --image ghcr.io/me/app:latest      # webhook: OATH_QUORUM=2
```
Той, хто вкрав ключ CI, може записати фальшивий digest, але другий запис від затверджувача зробити не може, і кворум не набирається. Перевірено на живому devnet: digest із двома записами проходить (`quorum 2/2`), digest лише з записом CI не проходить.

**Про апаратні ключі чесно.** Кворум захищає, якщо ключ затверджувача зберігається окремо від CI, але підписувати апаратним ключем *всередині CI* неможливо (там нема пристрою), а підпис Ledger/гаманцем у цей інструмент **не реалізований і не тестувався**: `anchor.mjs` підписує ключем із файлу. Тобто апаратне зберігання ключа затверджувача лишається справою оператора; ми гарантуємо лише, що без другого незалежного запису деплой не пройде.

## Затвердження й відкликання з кошилька
`verifier/approve.html` (на сайті: https://tymofii-thc.github.io/oath/approve.html) дозволяє людині-затверджувачу додати другий підпис кворуму або відкликати digest із браузерного кошилька (Phantom, Solflare; обидва працюють із Ledger). Сторінка будує одну Memo-транзакцію, показує, що саме підписується, і просить кошилька підписати; приватний ключ до сторінки не потрапляє. Перед затвердженням звір digest із логом CI.
**Перевірено** зі справжнім Phantom (розширення браузера) на живому devnet: транзакцію сторінки підписав гаманець, її прийнято, а `oath verify --quorum 2` пройшов (і не пройшов з одним лише ключем CI). Підпис також підтверджено зі справжнім Solflare (2026-10-20). **Не перевірено** з Ledger.

## Мейннет
Усе працює однаково: `--network mainnet` (CLI), `OATH_NETWORK=mainnet` (webhook), `?net=mainnet` або випадайка (сторінка), для запису в CI вхід `rpc` action'у (або змінна репозиторію `SOLANA_RPC`). Запис коштує приблизно 0,000005 SOL комісії. Сторінка-верифікатор для мейннету ходить у `solana-rpc.publicnode.com`, бо `api.mainnet-beta.solana.com` повертає 403 на всі браузерні запити (заголовок `Origin`); CLI й webhook це не зачіпає. Публічний RPC `api.mainnet-beta.solana.com` має ліміти, для продакшену візьми власний (Helius, QuickNode тощо) і передай через `--rpc` / `SOLANA_RPC`.

## Ключі: ротація, відкликання, строк дії
- `--signer a,b` / `OATH_SIGNER=a,b` приймає кілька ключів (достатньо запису від будь-якого, якщо не задано `--quorum`). **Ротація:** додай новий ключ → переключи CI → через потрібний час прибери старий.
- **Відкликання ключа:** прибери скомпрометований ключ зі списку; усі його записи перестають діяти одразу (це політика перевірки, а не дані в блокчейні).
- **Відкликання digest:** `oath revoke --digest sha256:… --reason "…"` (з `SOLANA_SECRET_KEY` або `--key-file`) записує підписаний запис про відкликання. Відкликання від **будь-якого довіреного підписанта остаточне**: цей digest більше ніколи не пройде перевірку, навіть якщо його знову записали пізніше. `verify` і `audit` показують `REVOKED` із причиною. Так ти позначаєш фальшивий запис, щойно помітив, не чекаючи на ротацію ключа.
- `--max-age <днів>`: старі записи не приймаються, тож вкрадений давній digest не живе вічно.
- Запис привʼязаний до імені образу: digest, зафіксований для `ghcr.io/me/other`, не підтвердить `ghcr.io/me/app` (вимикається `--no-bind`).
- Перевірка гортає історію підписанта (до `--limit` транзакцій, 1000 за замовчуванням), а не лише останні 100.

## Доступність
- `--rpc a,b,c` / `SOLANA_RPC=a,b,c`: кілька RPC пробуються по черзі, тож один недоступний чи обмежений endpoint не блокує перевірку. Якщо недоступні всі, перевірка все одно fail closed.
- Відповідь `429` від endpoint одразу веде до наступного endpoint; лише коли відмовили всі й хоч один дав 429, іде пауза з наростанням і новий круг (`OATH_RPC_RETRIES` кругів, за замовчуванням 3). З одним endpoint це просто повтор із паузою.
- Webhook відповідає в межах `OATH_DEADLINE_MS` (за замовчуванням 12000, менше за 15 с API-сервера): повільна перевірка дає зрозумілу відмову («verification took longer than 12s; retry shortly») замість невиразного «failed calling webhook», а сама перевірка доробляє у фоні й заповнює кеш, тож повтор зазвичай миттєвий.
- У кластері URL RPC зберігається в Secret (`oath-rpc`; Helm: `rpc`, або `rpcSecret` зі своїм іменем), бо в URL зазвичай є API-ключ.
- Примітка «single-signer verification» у `oath verify` друкується лише в інтерактивному терміналі (вимкнути: `OATH_QUIET=1`), тож логи CI лишаються чистими.
- Webhook тримає короткий результат для кожного перевіреного образу. З `OATH_STALE_OK_HOURS` (за замовчуванням 1; `0` = строго fail closed) образ, перевірений у цьому вікні, і далі допускається, поки RPC недоступний. Записи незмінні, тож єдине, що це може пропустити, це відкликання, зроблене під час збою.
- `deploy/install.sh` також ставить CronJob (щогодини за замовчуванням; `OATH_AUDIT_SCHEDULE="*/30 * * * *"` міняє розклад, `OATH_AUDIT_SCHEDULE=off` вимикає), що запускає `oath audit --in-cluster`, і один раз запускає його одразу після встановлення, тож Pod-и, які працювали до webhook, теж перевіряються. Job, що знайшов непідтверджений чи відкликаний образ, завершується помилкою: `kubectl -n oath-system get jobs`. У Helm-чарті той самий щогодинний CronJob (`auditSchedule`, порожнє = вимкнено).

## Сканування вразливостей (необовʼязково)
Oath доводить походження, а не безпеку. Щоб не підписувати вразливі образи, встанови змінну репозиторію `OATH_SCAN=true`: тоді Trivy перед записом перевіряє образ на виправні CRITICAL, а при знахідках запис у Solana не створюється, і крок `deploy` не пройде.

## Запусти демо сам
Скрипт показує всю історію: збирає образ, записує його в Solana, перевіряє, потім підміняє образ під тим самим тегом і показує, що перевірка не проходить.
```bash
SOLANA_SECRET_KEY="$(cat .oath/ci-key.json)" demo/demo.sh     # потрібні docker і поповнений devnet-ключ (див. `oath init`)
```
Очікуй `VERIFIED` з кодом 0, потім `NOT VERIFIED` з кодом 1. Ті самі дві перевірки є в [живому верифікаторі](https://tymofii-thc.github.io/oath/) по одному кліку.

## Ще
- [THREAT-MODEL.md](THREAT-MODEL.md) (англійською): атаки, що відбувається, що не покрито, і що знайшов огляд безпеки коду (зокрема діру з підробкою записів, відтворену й закриту).
- Webhook перевіряє і `UPDATE` (зміна образу працюючого Pod-а, `kubectl debug`), віддає метрики Prometheus на `/metrics`, має необов'язкові `OATH_ALLOWED_REGISTRIES` (реєстри, до яких він може звертатися) та `OATH_LIMIT` (скільки транзакцій сканувати на підписанта).

## Обмеження (скажи сам, перш ніж запитають)
- **Ключ CI.** Хто вкраде `SOLANA_SECRET_KEY`, може записати фальшивий digest. Кворум із незалежним ключем затверджувача це закриває, але потребує людини в процесі й окремо збереженого ключа; без кворуму лишаються лише пом'якшення (ротація, відкликання, `--max-age`, привʼязка до образу). Апаратні ключі й підпис Ledger у цей інструмент **не реалізовані**.
- **Чесність збірки.** Запис у Solana доводить лише «підписант зафіксував digest». Атестацію походження збірки (SLSA через Sigstore) перевіряє `--attest`; вона доводить, що digest зібрав саме workflow вказаного репозиторію, але не що сам код безпечний (для вразливостей є необов'язковий Trivy-гейт).
- **Мережа.** За замовчуванням devnet (безкоштовно, але без гарантій зберігання). Мейннет підтримується; для CI є ручний workflow `anchor-mainnet` (секрет `SOLANA_SECRET_KEY_MAINNET`, потрібні копійки SOL). На живому мейннеті ми CI ще не проганяли.
- **Реєстр і RPC як залежності.** Webhook fail-closed, тож при недоступності RPC чи реєстру нові Pod не створюються (працюючі не чіпаємо). Для продакшену потрібен надійний RPC.
- **Pod-и, створені до встановлення webhook,** не блокуються (webhook бачить лише нові); їх перевіряють при встановленні й щогодини, тож поганий образ буде показано, але не зупинено.
- Аналог без блокчейну: Sigstore/Rekor. Наша відмінність: публічний журнал, що не залежить від одного оператора.

## Тести
```bash
npm test                      # юніт-тести (мок Solana RPC, кворум, атестації, admission-логіка, audit)
OATH_SIGNER=… OK_IMAGE=alpine:3.20 BAD_IMAGE=nginx:alpine test/e2e-kind.sh   # потрібні docker, kind, kubectl
```
