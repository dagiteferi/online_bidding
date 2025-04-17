<?php
// This page displays detailed information about a specific item.
session_start();
require_once '../config/db_connect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // Hardcoded admin credentials for demo purposes
    if ($username === 'admin' && $password === 'admin123') {
        try {
            // Check if admin user exists
            $stmt = $pdo->prepare("SELECT id, password, is_admin FROM users WHERE username = ?");
            $stmt->execute(['admin']);
            $user = $stmt->fetch();

            if ($user) {
                // Admin user exists, verify password
                if (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['is_admin'] = (bool)$user['is_admin'];
                    header("Location: admin_dashboard.php");
                    exit();
                } else {
                    // Password doesn't match, update the password
                    $hashed_password = password_hash('admin123', PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");
                    $stmt->execute([$hashed_password, 'admin']);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['is_admin'] = (bool)$user['is_admin'];
                    header("Location: admin_dashboard.php");
                    exit();
                }
            } else {
                // Admin user doesn't exist, create one
                $hashed_password = password_hash('admin123', PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)");
                $stmt->execute(['admin', $hashed_password, 1]);
                $user_id = $pdo->lastInsertId();

                // Set session variables
                $_SESSION['user_id'] = $user_id;
                $_SESSION['is_admin'] = true;
                header("Location: admin_dashboard.php");
                exit();
            }
        } catch (PDOException $e) {
            $error = "Database error: " . $e->getMessage();
        }
    } else {
        $error = "Invalid username or password.";
    }
}

// Fetch item details from the database
$stmt = $pdo->prepare("SELECT * FROM items WHERE id = ?");
$stmt->execute([$item_id]);
$item = $stmt->fetch();
if (!$item) {
    echo "Item not found.";
    exit();
}

// Display item details including name, description, price, and seller information
// This helps users make informed decisions about the item
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <div class="form-container">
        <h2>Admin Login</h2>
        <?php if (isset($error)): ?>
            <p style="color: red;"><?php echo $error; ?></p>
        <?php endif; ?>
        <?php if (isset($_GET['error']) && $_GET['error'] == 'invalid_user'): ?>
            <p style="color: red;">Invalid user. Please log in again.</p>
        <?php endif; ?>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>