import json
from math import fabs
from random import randint, choice

def generate():
    math_signs = ["+", "-", "x"]

    eq = str(randint(1, 101)) + " "
    for _ in range(randint(2, 5)):
        eq += str(choice(math_signs)) + " "
        eq += str(randint(1, 101)) + " "
    
    return eq

if __name__=='__main__':
    questions = {}
    for i in range(500):
        eq = generate()
        eq = eq.replace('x', '*')
        not_right = eval(eq)
        not_right += randint(int(fabs(not_right//4)), int(fabs(not_right//2)))
        questions[eq] = not_right
    
    json.dump(questions, open( "questions.json", 'w' ) )