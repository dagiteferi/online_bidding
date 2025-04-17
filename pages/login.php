<?php
// This page handles user login functionality.
session_start();
require_once '../config/db_connect.php';

// Initialize error variable
$error = null;

// Check user credentials and start session
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Trim inputs to remove whitespace
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    // Query the database for the user
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE LOWER(username) = LOWER(?)");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        // Debug logging
        file_put_contents('debug.log', "Username entered: '$username'\n", FILE_APPEND);
        file_put_contents('debug.log', "Password entered: '$password'\n", FILE_APPEND);
        file_put_contents('debug.log', "User found: " . ($user ? 'true' : 'false') . "\n", FILE_APPEND);
        if ($user) {
            file_put_contents('debug.log', "Stored hash: " . $user['password'] . "\n", FILE_APPEND);
            file_put_contents('debug.log', "Password verify: " . (password_verify($password, $user['password']) ? 'true' : 'false') . "\n", FILE_APPEND);
            file_put_contents('debug.log', "is_admin: " . $user['is_admin'] . "\n", FILE_APPEND);
        }

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = (bool)$user['is_admin'];

            file_put_contents('debug.log', "Login successful. Session: " . print_r($_SESSION, true) . "\n", FILE_APPEND);

            // Redirect based on admin status
            if ($_SESSION['is_admin']) {
                header("Location: admin_dashboard.php");
            } else {
                header("Location: user_dashboard.php");
            }
            exit();
        } else {
            $error = "Invalid username or password.";
            file_put_contents('debug.log', "Login failed: Invalid username or password.\n", FILE_APPEND);
        }
    } catch (PDOException $e) {
        $error = "Database error: Please try again later.";
        error_log("Login error: " . $e->getMessage());
        file_put_contents('debug.log', "Database error: " . $e->getMessage() . "\n", FILE_APPEND);
    }
}

// Display login form with error messages if any
// This ensures users can retry login if they fail
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="../javaScript/scripts.js"></script>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar">
        <div class="inner-width">
            <a href="../index.php" class="logo"></a>
            <button class="menu-toggler">
                <span></span>
                <span></span>
                <span></span>
            </button>
            <div class="navbar-menu">
                <a href="../index.php">Home</a>
                <a href="../index.php#about">About</a>
                <a href="../index.php#contact">Contact</a>
                <a href="login.php">Login</a>
            </div>
        </div>
    </nav>

    <div class="body">
        <div class="continer">
            <div class="card" id="card">
                <div class="div1">
                    <h2>LOGIN</h2>
                    <?php if ($error): ?>
                        <p style='color: red; text-align: center;'><?php echo htmlspecialchars($error); ?></p>
                    <?php endif; ?>
                    <form method="POST">
                        <input type="text" name="username" class="input" id="input1" placeholder="your username" required>
                        <input type="password" name="password" class="input" id="input2" placeholder="your password" required>
                        <button type="submit" class="submit-btn" name="login">Submit</button>
                    </form>
                    <a href="register.php">
                        <button type="button" class="btn" style="margin-top: -7px;">Create an account</button>
                    </a>
                    <a href="reset.php">Forgot Password</a>
                </div>
            </div>
        </div>
    </div>
    <footer>
        <div class="copyright">
            © 2024 | Created & Designed By <a href="#home">Group 8</a>
        </div>
        <div class="sm">
            <a href="#/"><i class="fa fa-facebook" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-instagram" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-telegram" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-github" style="font-size:24px"></i></a>
        </div>
    </footer>
</body>
</html>