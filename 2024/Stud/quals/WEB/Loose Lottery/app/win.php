<?php
session_start();

if (!isset($_SESSION['user_id']) || !$_SESSION['winner']) {
    header('Location: index.php');
    exit;
}

$uploadDir = 'uploads/' . $_SESSION['user_id'] . '/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['info'])) {
        $_SESSION['info'] = htmlspecialchars($_POST['info']);
    }

    if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {

        $allowedTypes = ['image/jpeg'];
        $fileTmpPath = $_FILES['photo']['tmp_name'];
        $fileName = 'user.jpg';

        $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($fileInfo, $fileTmpPath);
        finfo_close($fileInfo);

        if (!in_array($mimeType, $allowedTypes)) {
            echo 'Only JPG files are allowed.';
            exit;
        }

        $photoFile = $uploadDir . $fileName;
        if (move_uploaded_file($fileTmpPath, $photoFile)) {
            $_SESSION['photo'] = $photoFile;
        } else {
            echo 'Error uploading photo.';
        }
    }

    header('Location: winners.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>YOU WON!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<div class="winner-header text-center">
    <h1>CONGRATULATIONS!</h1>
    <h2>You are a Winner!</h2>
</div>

<div class="winner-prize-banner">
    CLAIM YOUR PRIZE NOW!!!
</div>

<div class="container text-center mt-5">
    <h3>Upload Your Celebration Photo!</h3>
    <form action="" method="post" enctype="multipart/form-data" class="mt-4">
        <div class="mb-3">
            <input type="text" name="info" class="form-control" placeholder="A little bit about yourself" required>
        </div>
        <div class="mb-3">
            <input type="file" name="photo" class="form-control" required>
        </div>
        <div class="mb-3">
            <button type="submit" class="btn btn-danger btn-lg">Upload</button>
        </div>
    </form>

    <a href="winners.php" class="d-block mt-3 text-decoration-none">Other winners</a>
</div>

<footer class="text-center mt-5 py-4" style="background-color: #4caf50; color: white;">
    <p>© 2024 SCAM INC. All rights reserved.</p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
</body>
</html>


