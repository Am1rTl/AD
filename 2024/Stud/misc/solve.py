from pwn import *

# Connect to the remote server
io = remote("mctf-game.ru", 4445)



ans = {'61 * 1 + 71 + 80 - 101 * 33  = ?': 'A', '68 + 27 + 20 + 87  = ?\n': 'B', '73 * 16 - 50  = ?\n': 'A', '63 + 97 - 75 - 61 + 30 * 19  = ?\n': 'B', '29 + 68 - 50 + 64 + 69  = ?\n': 'C', '76 * 93 + 12 * 23 - 54 * 94  = ?\n': 'B', '10 - 71 + 6 - 87 - 22 - 33  = ?\n': 'C', '61 + 90 * 64 - 8 + 20  = ?\n': 'A', '83 - 55 - 33  = ?\n': 'A', '78 + 79 * 65 * 44  = ?\n': 'A', '101 - 96 - 61 + 82 + 73 * 65  = ?\n': 'C', '25 + 36 * 32 - 57 * 49 - 26  = ?\n': 'A', '30 + 83 - 98 - 24  = ?\n': 'C', '58 + 32 - 27 + 59 + 6  = ?\n': 'D', '5 + 48 - 17 * 82  = ?\n': 'A', '92 * 7 * 72  = ?\n': 'A', '30 + 1 - 61 + 25 - 89 * 32  = ?\n': 'C', '51 - 57 + 46 * 9 * 101 * 25  = ?\n': 'C', '31 + 16 + 65 - 94  = ?\n': 'C', '77 + 37 - 77 * 43 * 93  = ?\n': 'C', '6 + 42 * 85 + 8 * 68 + 36  = ?\n': 'D', '28 + 88 * 98 * 54 * 15 - 65  = ?\n': 'D', '4 * 67 * 100 + 85 + 4 * 69  = ?\n': 'A', '82 + 64 * 89 - 24 - 73 - 12  = ?\n': 'D', '47 + 14 - 61  = ?\n': 'B', '91 - 68 - 75 + 62 - 48  = ?\n': 'D', '76 + 14 * 3 + 45 * 84 + 93  = ?\n': 'B', '33 + 62 - 79 * 92  = ?\n': 'B', '62 + 23 * 84  = ?\n': 'A', '93 - 43 - 90 - 80 - 7 + 92  = ?\n': 'C', '53 - 23 * 52 - 93 + 26 - 70  = ?\n': 'B', '15 * 91 - 33 + 84 + 70 * 52  = ?\n': 'B', '67 + 82 + 89  = ?\n': 'B', '65 * 98 - 39  = ?\n': 'A', '95 + 80 - 60 - 11 - 98 - 99  = ?\n': 'A', '33 - 69 + 8 - 33 + 14  = ?\n': 'B', '14 * 29 * 49 + 29 + 5  = ?\n': 'A', '31 + 83 - 39 + 14 + 62 * 77  = ?\n': 'D', '34 * 84 * 48  = ?\n': 'B', '46 - 81 - 33 - 2  = ?\n': 'B'}


question = io.recv().decode()
index = question.find("---------------")

temp = question

question = question[index:]
question = question.split('\n')

rand_ans = ["A", "B", "C", "D"]


print(question)
q = question[2]

A = int(question[4].split('\t')[0].split(' ')[1])
B = int(question[4].split('\t')[2].split(' ')[1])
C = int(question[5].split('\t')[0].split(' ')[1])
D = int(question[5].split('\t')[2].split(' ')[1])

print(q,A,B,C,D)

if q not in ans.keys():
    tmp_ans = rand_ans[random.randint(0,3)]
    io.sendline(tmp_ans.encode())
    feedback = io.recvline().decode()
    print(feedback)
    if feedback.find("No(") != -1:
        print("nononono")
        anst = io.recvline().decode()
        anst = int(anst[anst.find("-")+1:])
        if anst == A:
            ans[q] = "A"
        elif anst == B:
            ans[q] = "B"
        elif anst == C:
            ans[q] = "C"
        else:
            ans[q] = "D"
        
    if feedback.find("Correct!") != -1:
        ans[q] = tmp_ans
else:
    io.sendline(str(ans[q]).encode())

print("The answers is:", ans)





while True:
    if feedback.find("No(") != -1:
        q = io.recvline().decode()
        q = io.recvline().decode()
    else:
        q = io.recvline().decode()

    if q[0] == 'R':
        q = io.recvline().decode()
        q = io.recvline().decode()
    AandB = io.recvline().decode()
    AandB = io.recvline().decode()
    CandD = io.recvline().decode()
    A = AandB.split('\t')[0]

    print("Question is", q.encode())
    q = q.encode()


    
    A = int(A.split(' ')[1])
    
    B = int(AandB.split('\t')[2].split(' ')[1])
    C = int(CandD.split('\t')[0].split(' ')[1])
    D = int(CandD.split('\t')[2].split(' ')[1])
    temp = io.recvline()
    if q not in ans.keys():
        tmp_ans = rand_ans[random.randint(0,3)]
        print("Use random")
        io.sendline(tmp_ans.encode())
        feedback = io.recvline().decode()
        print(feedback)
        if feedback.find("No(") != -1:
            print("nononono")
            anst = io.recvline().decode()
            anst = int(anst[anst.find("-")+1:])
            if anst == A:
                ans[q] = "A"
            elif anst == B:
                ans[q] = "B"
            elif anst == C:
                ans[q] = "C"
            else:
                ans[q] = "D"
            
        if feedback.find("Correct!") != -1:
            ans[q] = tmp_ans
            
    else:
        io.sendline(str(ans[q]).encode())

   # print(ans)
    
    


"""
    expression = question.split('=')[0].strip()  # Get everything before '='
    
    # Calculate the answer using eval (ensure safety in a controlled environment)
    try:
        answer = eval(expression)  # Evaluate the expression
    except Exception as e:
        print(f"Error evaluating expression: {e}")
        break

    # Send back the answer
    io.sendline(str(answer).encode())

    # Optionally, receive feedback about whether the answer was correct
    feedback = io.recvline().decode()
    print(feedback)  # Print feedback for debugging
    """

# Close connection when done
io.close()
