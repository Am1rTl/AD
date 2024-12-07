package main

import (
    "os"
    "strings"
)

const mappedFlag = "p8xsi8dlba61rb9q0obhpr8qhbhuojrjqrjqshr1uoqjrpmu6g"

var lookupTable = map[rune]rune{
    'v': 'w', 'j': '5', 't': 'x', '}': 'g', 'y': 'o', 'z': 'e', 'i': '{', 'h': '4', 'n': 'b', 'c': '8',
    'm': 'p', 'a': '7', 'l': 'u', '_': 'q', '0': 'd', 'f': 's', '2': 'k', '3': '6', '1': 'r', '9': '9',
    'r': '1', '6': '3', 'k': '2', 's': 'f', 'd': '0', 'q': '_', 'u': 'l', '7': 'a', 'p': 'm', '8': 'c',
    'b': 'n', '4': 'h', '{': 'i', 'e': 'z', 'o': 'y', 'g': '}', 'x': 't', '5': 'j', 'w': 'v',
}

func main() {
    if len(os.Args) != 2 {
        os.Exit(1)
    }

    isFlagCorrect := strings.Map(
        func(r rune) rune {
            newRune, ok := lookupTable[r]

            if ok {
                return newRune
            }

            return r
        },
        os.Args[1],
    ) == mappedFlag

    if isFlagCorrect {
        os.Exit(0)
    } else {
        os.Exit(1)
    }
}
