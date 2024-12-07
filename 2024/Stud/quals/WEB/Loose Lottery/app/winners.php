<?php
session_start();

if (!isset($_SESSION['user_id']) || !$_SESSION['winner']) {
    header('Location: index.php');
    exit;
}

$firstWinner = [
    'name' => 'First Winner',
    'photo' => 'uploads/' . ($_SESSION['user_id']) .'/first.jpg',
];

$userInfoAvailable = isset($_SESSION['info']) && isset($_SESSION['photo']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Previous Winners</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<div class="winner-header text-center">
    <h1>Previous Winners</h1>
</div>

<div class="container mt-5">
    <h3 class="text-center">Congratulations to Our Lucky Winners!</h3>
    <div class="winner-list">
        <ol class="list-group">
            <li class="list-group-item text-center">
                <strong><?php echo $firstWinner['name']; ?></strong><br>
                <img src="<?php echo $firstWinner['photo']; ?>" alt="First winner" class="img-fluid" style="max-height: 200px;"><br>
                <a href="winner.php?winner=first.jpg" class="btn btn-info mt-2">Learn More</a>
            </li>
            <?php if ($userInfoAvailable): ?>
                <li class="list-group-item text-center">
                    <strong>You</strong><br>
                    <img src="<?php echo $_SESSION['photo']; ?>" alt="Your photo" class="img-fluid" style="max-height: 200px;"><br>
                    <a href="winner.php?winner=user.jpg" class="btn btn-info mt-2">Learn More</a>
                </li>
            <?php endif; ?>
        </ol>
    </div>
    <div class="text-center mt-4">
        <a href="/win.php" class="btn btn-secondary">Back to Upload Page</a>
    </div>
</div>

<footer class="text-center mt-5 py-4" style="background-color: #4caf50; color: white;">
    <p>© 2024 SCAM INC. All rights reserved.</p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
</body>
</html>