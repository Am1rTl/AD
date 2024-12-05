package main

import (
  "bufio"
  "encoding/base64"
  "fmt"
  "os"
  "strings"
  "time"
)

func main() {
  whoami := "Who am I?"
  answer := "Ayanami Rei"
  iter := 1000000000
  var userInput string
  var isSuccess int = 0

  for i := 0; i < iter; i++ {
    fmt.Println(whoami)
    reader := bufio.NewReader(os.Stdin)
    userInput, _ = reader.ReadString('\n')
    if strings.TrimRight(userInput, "\r\n") == answer {
      isSuccess += 1
    }
    time.Sleep(time.Second)
    fmt.Println()
  }
  if isSuccess == iter {
    var flag string = "😶🥴😋🥳😰💀🤓🤬🥶☹️🤬😱😴🤡💀😈🎃🥴😬🥵🎃🤒🤓😎🤫😴😋🤪🥶🤯🤬😶😇🥴😭😈😘💀🙃😍"
    flag = strings.ReplaceAll(flag, "🤪", "P")
    flag = strings.ReplaceAll(flag, "🤓", "Y")
    flag = strings.ReplaceAll(flag, "😈", "S")
    flag = strings.ReplaceAll(flag, "😍", "=")
    flag = strings.ReplaceAll(flag, "😶", "O")
    flag = strings.ReplaceAll(flag, "☹️", "z")
    flag = strings.ReplaceAll(flag, "🥴", "g")
    flag = strings.ReplaceAll(flag, "😘", "X")
    flag = strings.ReplaceAll(flag, "🤯", "A")
    flag = strings.ReplaceAll(flag, "🎃", "M")
    flag = strings.ReplaceAll(flag, "😭", "t")
    flag = strings.ReplaceAll(flag, "🥶", "D")
    flag = strings.ReplaceAll(flag, "🤡", "R")
    flag = strings.ReplaceAll(flag, "🥵", "d")
    flag = strings.ReplaceAll(flag, "🤫", "E")
    flag = strings.ReplaceAll(flag, "😴", "V")
    flag = strings.ReplaceAll(flag, "😱", "m")
    flag = strings.ReplaceAll(flag, "😋", "s")
    flag = strings.ReplaceAll(flag, "🤒", "T")
    flag = strings.ReplaceAll(flag, "💀", "x")
    flag = strings.ReplaceAll(flag, "😬", "c")
    flag = strings.ReplaceAll(flag, "🙃", "w")
    flag = strings.ReplaceAll(flag, "😎", "W")
    flag = strings.ReplaceAll(flag, "😇", "H")
    flag = strings.ReplaceAll(flag, "😰", "B")
    flag = strings.ReplaceAll(flag, "🤬", "Q")
    flag = strings.ReplaceAll(flag, "🥳", "b")

    data, err := base64.StdEncoding.DecodeString(flag)
    if err != nil {
      os.Exit(0)
    }
    fmt.Println(xor(string(data), strings.ReplaceAll(whoami+answer, " ", "")))
  }
}

func xor(input, key string) (output string) {
  for i := 0; i < len(input); i++ {
    output += string(input[i] ^ key[i%len(key)])
  }
  return output
}