<?php
if (isset($_GET["source"])) highlight_file(__FILE__) && die();

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

chdir('uploads/' . $_SESSION['user_id']);
class UserInfo
{
    public $name;
    public $info;
    public $photo;
    private $deletePhoto = false;

    public function __construct($info, $photo, $name)
    {
        $this->name = $name;
        $this->info = $info;
        $this->photo = $photo;
    }

    public function requestDelete()
    {
        $this->deletePhoto = true;
    }

    public function __destruct()
    {
        if ($this->deletePhoto && $this->photo) {
            echo shell_exec('rm ' . $this->photo);
            $this->photo = '';
        }
    }
}

function getWinnerInfo()
{
    if (isset($_GET['winner'])) {
        if ($_GET['winner'] === 'first.jpg') {
            return new UserInfo(
                'Legend.',
                'uploads/' . ($_SESSION['user_id']) .'/first.jpg',
                'First Winner'
            );
        } else if (!strpos($_GET['winner'], "..") && file_exists($_GET['winner'])) {
            return new UserInfo(
                isset($_SESSION['info']) ? $_SESSION['info'] : 'No information',
                isset($_SESSION['photo']) ? $_SESSION['photo'] : '',
                'You'
            );
        }
    }
    return null;
}

$winner = getWinnerInfo();

if (isset($_GET['delete'])) {
    $winner->requestDelete();
    header("Location: winner.php?winner=user.jpg");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Winner Info</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<div class="winner-header text-center">
    <h1>Winner Information</h1>
</div>

<div class="container mt-5">
    <h3 class="text-center"><?php echo $winner->name; ?></h3>
    <div class="row justify-content-center">
        <div class="col-md-6 text-center">
            <div class="card mb-4 shadow-sm">
                <div class="card-body">
                    <h5 class="card-title">About Winner</h5>
                    <p class="card-text"><?php echo $winner->info; ?></p>
                </div>
            </div>
            <?php if ($winner->photo): ?>
                <div class="card mb-4 shadow-sm winner-card">
                    <img src="<?php echo $winner->photo; ?>" class="card-img-top" alt="Winner's photo">
                </div>
            <?php else: ?>
                <div class="alert alert-warning" role="alert">
                    No photo uploaded.
                </div>
            <?php endif; ?>
        </div>
    </div>
    <div class="text-center mt-4">
        <a href="winners.php" class="btn btn-primary">Return to the winners list</a>
        <?php if ($winner->name === 'You'): ?>
            <a href="winner.php?winner=user.jpg&delete" class="btn btn-danger">Delete Photo</a>
        <?php endif; ?>
        <a href="win.php" class="btn btn-secondary">Back to Upload Page</a>
    </div>

    <a href="?source" class="btn btn-outline-secondary" id="view-source-btn">View Source Code</a>
</div>

<footer class="text-center mt-5 py-4" style="background-color: #4caf50; color: white;">
    <p>© 2024 SCAM INC. All rights reserved.</p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
</body>
</html>




