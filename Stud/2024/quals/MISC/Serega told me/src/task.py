import json
from math import fabs
from time import sleep
from os import environ
from random import choice, shuffle, randint

questions = json.load(open( "questions.json" ))
answer_choice = {"a": 0, "b": 1, "c":  2, "d": 3}

def get_question():
    question, answer = choice(list(questions.items()))
    answers = [answer, answer + randint(int(fabs(answer//4)), int(fabs(answer//2))), answer + randint(int(fabs(answer//3)), int(fabs(answer))), answer + randint(int(fabs(answer//7)), int(fabs(answer//4)))]
    shuffle(answers)
    return question, answer, answers

if __name__=='__main__':
    print("""
......................................................................
...............=+#@@@@@@@@#%@@@@@@@@@@@@@@@@@@@@@@@@@@:::..::::::::::.
............:::+:-@#@#@#@@#-%@+*==#@-:@#%:%*@=+@=@:+@@.::.:::::::::::.
............:::=+#@@@@@@@@#%@@@@@@@@@@@@@@@@@@@@@%@@@@::::::::.::::::.
.....:@@@...-=-@@@:::@@@@%@#@@@@@@@::::@@@-@#@@@@@%@%:@@@@@@@@@@:::::.
.....:@:@::-@@@@=@.::@#@=@+#@*::#@@:::+@+@@*#+@##@#:%%@:%@@@*%@@:.::..
.:::::@@@:.=@+@@+@@@+@@@*%@*@@@@@@@:::#@@%%+*@@@@@%@#:#@@@@@@@@@:::::.
.::::::::.:-@@#@@@@@@@@@-+=+#+::#@#:::+*+=%#=:-=-:::+#*:#@%#+%@%:::::.
.:::::::::.+@@@@@-@@+-@@@%:::::--::::::=@@@@@@@@@+:::::::::-------::-.
.:-------::@@@@#@@@@@@@@@@*::---:::-::+@@@#***#%@@*---:--=+++++++=---.
.-:--==-==-@@=@@@@*%@@*@-@@------:::-=@@-%@@@@@@=@@=::-=+###**+++*###.
.+=:--::--:@@#*%@@*@@@@@@@@------++=-*%++-:::-#@@@@+:=#%%#*+==-:+*+--.
.*%*--==--:@@@=*%@%@@@@@@@@:=--=-==*++%#@@@@#-%@@@@@:*+---=+++-==:+=-.
.+-#=-:---:#@@*@@@@:%@%#%%@:-=-::=+++-*@@@@@@=@@=#@@-+*#%#=-:=+=--=-:.
.#=++*#%#+-*@@%+=:@%**#*=%*::--::::---=@@@%@@*@@#%@@-=-::+-=-:--:--:-.
.@*-+*+#%@#++@@%=-##+#=*#-::::---=*##%+@@@@@#+#+**@@=-=:-=----:--::::.
.-*+*+==+*=++-%@%-+*@*++%@@@@@@@@@@@@@@+#=--+##=-=@@%#=--+=---:::-=*@.
.-==*#*#%%*==@@@*-==#*::@@@@@@@@@@@@@@@*#=++====+=%@@@@+--=+#*====*%=.
.=---=+-:=+#@%@#+-=-=+*#@**#=---=+--+=@+@@#:=-+#@@=#@@@@-:+%**=#@@#*#.
.==--+#+-=+@@@@@++--**##+*+=++==+=-*%%@@@##*+**=--*+--@@=-=%*=++-*@@@.
.@%#@@@@@*+@@@#+==:+=+::----:---=+**-=+=-#*+==-+#%+-*@@@=:+#+=+:=-+@@.
.@@%@@@@@@@@@===:-:+=-::---:::::=*+*%%###+++--+++==-:=%*%**#+#+*=-##+.
.+##@+==#@@@+=-::---::---::::::+@@@%+==-::::--:-----::#@@@#*+@%+#:%@+.
.*=@@:=*-==*=::::-:::::::::::--@@@@@@+--::::::::-:-:::=*#@@@@@*-*#-@%.
.#-@*-*-+=++-::::::::::::--:::+@#@+:#+:---::-:-:-:::----=%@@#==--*++@.
.%*@--==-#+-:::::::--:==-==---%%-==-*#-=:::-:--:-:::--::--+*-===*%%%@.
.+-%%@@@**+-:::::=++=-=+-=+--=@%#-**#@*+=-::-:-:::-=-:---:=*=#%@@@@#%.
.++#@@@@%*=##+====:-=:=+-=+-=@@=@-*#*%@:=-::-::--:--:----:-+#@@@#=---.
.---=-+@@+--==:--=+--=-+=:=-=#@-#+=-*#@-:=::::::::-:-:=-:::-%@#+:----.
.-=-=:=@@@*#*--==:-=--=+--=:-##-+:=#%@@=:---:::::-:=-=------@@=+--=::.
.-+=:+=@@@*-:-++=--::=--::---##:--+==%@*:::-:::::---:-==-::=@@::=*-=-.
.--==-#%@@#=====-:-=-:-::--:-*#++++*%#%*+-:-=-:::::--:::--:+@+:==+*=-.
.---=+#=@@:=+:+:-=--===::::=@@@@@*@@@@++-+----::::----:::--*%+===---:.
.:+:-=+*@@=:-+-==-:=-::::--*@@@-%@*+@@:%*+-=----:::::::::::**-+#**=:-.
.-+-=+-@@#=-===-:+=-:::---:#@@@@@@@@@@@@#++*+:::--:-:::-::-*+-=*#*=::.
.-=-+**@%=-:--:+*+----:::::##@%+@#@*@@***==:+::--:-:-:-:::-=*:+-=%*--.
.-=:-:%@+=-::++=:::::::-:::#%@@@@@@#@@@@#====:::-=:-::::::--*+=-=@+=-.
......................................................................
""")

    print("Hello!\nMy calculator isn't afraid to make mistakes! Are you afraid?..\n\nYou will have 120 attempts to answer 100 mathematical equations correctly.")
    print("---------------\n")

    attempt, right = 0, 0
    while ((right != 100) and (attempt != 120)):
        attempt += 1
        question, answer, answers = get_question()
        
        print(f"{question} = ?", end="\n\n")
        print(f"A) {answers[0]}\t\tB) {answers[1]}")
        print(f"C) {answers[2]}\t\tD) {answers[3]}", end="\n\n")

        c = input("You'r answer: ").lower()

        if c not in answer_choice:
            print("There is no such option(\n")
            continue

        if answers[answer_choice[c]] == answer:
            print("Correct!")
            right += 1
        else:
            print(f"No(\nRight answer - {answer}\n")

        if right == 100:
            print(f"You deserve it: {environ['FLAG']}")