<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = uniqid();
    $_SESSION['winner'] = false;
    $uploadDir = 'uploads/' . $_SESSION['user_id'] . '/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    copy('images/winner.jpg', $uploadDir . 'first.jpg');
}


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $number = $_POST["number"];
    if (strlen($number) <= 16) {
        if ($number == 72057594037927935) {
            $_SESSION['winner'] = true;

            header("Location: win.php");
            die();
        } else {
            $response = 'Sorry, try again';
        }
    } else {
        $response = 'Your number is too long';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LOOSE LOTTERY</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<div class="header text-center">
    <h1>SUPER MEGA JACKPOT!</h1>
    <h2>YOUR CHANCE TO BE A MILLIONAIRE!</h2>
</div>

<div class="prize-banner">
    WIN $1,000,000 RIGHT NOW!!!
</div>

<div class="container text-center mt-5">
    <h3>LIMITED TIME OFFER!</h3>
    <p class="lead">
        <strong>HURRY!</strong> Every ticket gives you the chance to WIN INCREDIBLE PRIZES: luxury cars, stacks of cash, dream homes, and even a PRIVATE ISLAND! Just <span class="text-danger">CLICK</span>, enter the NUMBER and watch your life change FOREVER!
    </p>
</div>

<div class="text-center mt-5">
    <button class="btn btn-custom" onclick="showInputField()">FREE MONEY!!!</button>
    <form method="post" action="" id="inputField">
        <p>Try to guess the secret number</p>
        <input type="text" class="form-control mt-3 custom-input" name="number" placeholder="Enter your number to get your ticket!" aria-label="Number Input">
        <!--72057594037927935-->
        <input type="submit" value="Submit" class="btn btn-primary mt-3">
    </form>
    <h2><?php echo isset($response) ? $response : ''; ?></h2>
</div>

<div class="container mt-5">
    <div class="row text-center">
        <div class="col-md-4">
            <img src="/images/car.jpg" class="rounded-circle" alt="Car">
            <h4 class="mt-3">Luxury Sports Car!</h4>
        </div>
        <div class="col-md-4">
            <img src="/images/cash.jpg" class="rounded-circle" alt="Money">
            <h4 class="mt-3">$1,000,000 Cash!</h4>
        </div>
        <div class="col-md-4">
            <img src="/images/island.jpg" class="rounded-circle" alt="Island">
            <h4 class="mt-3">Your Own Private Island!</h4>
        </div>
    </div>
</div>

<footer class="text-center mt-5 py-4" style="background-color: #f44336; color: white;">
    <p>© 2024 SCAM INC. All rights reserved.</p>
    <p><a href="#" class="text-white">Terms & Conditions</a> | <a href="#" class="text-white">Contact Us</a></p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
<script>
    function showInputField() {
        var inputField = document.getElementById('inputField');
        if (inputField.style.display === "none") {
            inputField.style.display = "block";
        } else {
            inputField.style.display = "none";
        }
    }
</script>
</body>
</html>
