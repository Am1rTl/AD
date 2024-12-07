from pwn import *

# Подключение к серверу
conn = remote('mctf-game.ru', 4040)
for i in range(1000):
    # Чтение данных с сервера
    data = conn.recvuntil('Input your meal id:').decode()
    print(data)
    data = data.split('\n')
    data = data[15:len(data)-2]
    print(data)


    # Парсинг данных и выбор максимального значения Bonus
    max_bonus = 0
    max_id = 0
    for id in range(0,len(data)):
        print(id, int(data[id][58:-2]), max_bonus)
        if int(data[id][58:-2]) > max_bonus:
            max_id = id+1
            max_bonus = int(data[id][58:-2])

    # Отправка ответа
    conn.sendline(str(max_id))
    print(f"Отправлен ответ: {max_id}")

# Закрытие соединения
conn.close()

