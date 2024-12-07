# PWN | Hard | Achilles

## Description
Description required.

```
nc mctf.ru 4444
```

## Writeup
Посмотрим на представленную ниже программу:

```python
import sys
from keyword import iskeyword
from keyword import issoftkeyword
from os import environ


print(
    '''

     ..                                       .          ..       ..               .x+=:.
  :**888H: `: .xH""              .uef^"      @88>  x .d88"  x .d88"               z`    ^%
 X   `8888k XX888              :d88E         %8P    5888R    5888R                   .   <k
'8hx  48888 ?8888          .   `888E          .     '888R    '888R        .u       .@8Ned8"
'8888 '8888 `8888     .udR88N   888E .z8k   .@88u    888R     888R     ud8888.   .@^%8888"
 %888>'8888  8888    <888'888k  888E~?888L ''888E`   888R     888R   :888'8888. x88:  `)8b.
   "8 '888"  8888    9888 'Y"   888E  888E   888E    888R     888R   d888 '88%" 8888N=*8888
  .-` X*"    8888    9888       888E  888E   888E    888R     888R   8888.+"     %8"    R88
    .xhx.    8888    9888       888E  888E   888E    888R     888R   8888L        @8Wou 9%
  .H88888h.~`8888.>  ?8888u../  888E  888E   888&   .888B .  .888B . '8888c. .+ .888888P`
 .~  `%88!` '888*~    "8888P'  m888N= 888>   R888"  ^*888%   ^*888%   "88888%   `   ^"F
       `"     ""        "P'     `Y"   888     ""      "%       "%       "YP'
                                     J88"
                                     @%
                                   :"

'''
)


def retreat():
    print('Better be a late learner than an ignorant..')


def conquer():
    print('Ten soldiers wisely led will beat a hundred without a head..')
    print(environ['FLAG'])


function = input('What would a wise polemarch do? [retreat / conquer] ')

if not function.isidentifier():
    sys.exit(f'Invalid identifier: {function!r}')
elif iskeyword(function) or issoftkeyword(function):
    sys.exit(f'Reserved identifier: {function!r}')
elif function == 'conquer':
    sys.exit('Option [conquer] is temporarily unavailable!')

try:
    global_variables = {
        '__builtins__': {},
        'retreat': retreat,
        'conquer': conquer,
    }

    eval(f'{function}()', global_variables)
except NameError:
    sys.exit(f'Option [{function}] is not available!')
```

Выделим из этой программы самое интересное:

```python
import sys
from keyword import iskeyword
from keyword import issoftkeyword
from os import environ


def retreat():
    print('Better be a late learner than an ignorant..')


def conquer():
    print('Ten soldiers wisely led will beat a hundred without a head..')
    print(environ['FLAG'])


function = input('What would a wise polemarch do? [retreat / conquer] ')

if not function.isidentifier():
    sys.exit(f'Invalid identifier: {function!r}')
elif iskeyword(function) or issoftkeyword(function):
    sys.exit(f'Reserved identifier: {function!r}')
elif function == 'conquer':
    sys.exit('Option [conquer] is temporarily unavailable!')

try:
    global_variables = {
        '__builtins__': {},
        'retreat': retreat,
        'conquer': conquer,
    }

    eval(f'{function}()', global_variables)
except NameError:
    sys.exit(f'Option [{function}] is not available!')
```

Анализ выше представленного кода:

1. В программе есть две функции `retreat` (отступить) и `conquer` (завоевать).
2. Программа запрашивает у пользователя имя функции, которую он хочет вызвать.
3. Первые два условия проверяют, что введенное имя функции является допустимым и не является ключевым словом.
4. Третья проверка запрещает пользователю вызывать функцию `conquer`, которая выводит флаг в консоль.
5. Имя функции форматируется и вызывается без аргументов через встроенную функцию `eval`.

Второй аргумент `eval` это список глобальных переменных, в котором указано, что можно вызывать только функции `retreat` или `conquer`, вызов встроенных функций запрещён.

Сообщение о вводе функции предлагает ввести `conquer`, но третья проверка не пропускает такой ввод, несмотря на то, что во втором аргументе `eval` указано, что вызов такой функции возможен. Но написать просто `conquer` мы опять же не можем. Получается можно ввести что-то, что вызовет `conquer` и при этом не будет равно `conquer`.

А что может быть валидным названием переменной? За получением ответа отправимся на просторы python документации, откуда можно узнать вот это:
1. Если в представлении исходного кода UTF-8 обнаружен символ, не входящий в ASCII, выполняется прямое сканирование для поиска первого символа ASCII, не являющегося идентификатором (например, пробела или знака пунктуации).
2. Вся строка UTF-8 передается в функцию для нормализации строки до NFKC, а затем проверяется, что она соответствует синтаксису идентификатора. Для идентификаторов в формате Pure-ASCII такой вызов не делается, и они продолжают анализироваться так же, как и сегодня. База данных Unicode должна начинаться с включения свойства Other_ID_{Start|Continue}.

Осталось только преобразовать `conquer` в другую форму через NFKC ;D

## Author
По вопросам, связанным с таском, обращаться к [@pavloff_dev](https://t.me/pavloff_dev).

## Flag
```
mctf{19n0r4nc3_15_b0ld_kn0wl3d93_15_r353rv3d}
```
