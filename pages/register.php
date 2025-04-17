<?php
require_once '../config/db_connect.php';

if (isset($_POST['signup'])) {
    function test_input($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }

    try {
        // Debug logging
        file_put_contents('debug.log', "Registration attempt:\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw first_name: '" . ($_POST['first_name'] ?? '') . "'\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw last_name: '" . ($_POST['last_name'] ?? '') . "'\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw email: '" . ($_POST['email'] ?? '') . "'\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw username: '" . ($_POST['username'] ?? '') . "'\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw password: '" . ($_POST['password'] ?? '') . "'\n", FILE_APPEND);
        file_put_contents('debug.log', "Raw confirm_password: '" . ($_POST['confirm_password'] ?? '') . "'\n", FILE_APPEND);

        // Validate first name
        if (empty($_POST['first_name'])) {
            throw new Exception("First name is required!");
        } else {
            $first_name = test_input($_POST['first_name']);
            if (!preg_match("/^[a-zA-Z-' ]*$/", $first_name)) {
                throw new Exception("Only letters and white space allowed in first name!");
            }
        }

        // Validate last name
        if (empty($_POST['last_name'])) {
            throw new Exception("Last name is required!");
        } else {
            $last_name = test_input($_POST['last_name']);
            if (!preg_match("/^[a-zA-Z-' ]*$/", $last_name)) {
                throw new Exception("Only letters and white space allowed in last name!");
            }
        }

        // Validate email
        if (empty($_POST['email'])) {
            throw new Exception("Email is required!");
        } else {
            $email = test_input($_POST['email']);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception("Invalid email format!");
            }
            // Check email uniqueness
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetchColumn() > 0) {
                throw new Exception("Email is already registered!");
            }
        }

        // Validate username
        if (empty($_POST['username'])) {
            throw new Exception("Username is required!");
        } else {
            $username = test_input($_POST['username']);
            if (!preg_match("/^[a-zA-Z0-9_-]*$/", $username)) {
                throw new Exception("Username can only contain letters, numbers, underscores, or hyphens!");
            }
            // Check username uniqueness
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetchColumn() > 0) {
                throw new Exception("Username is already taken!");
            }
        }

        // Validate password
        if (empty($_POST['password'])) {
            throw new Exception("Password is required!");
        } elseif (strlen($_POST['password']) < 6) {
            throw new Exception("Password must be at least 6 characters long!");
        }

        // Validate confirm password
        if (empty($_POST['confirm_password'])) {
            throw new Exception("Confirm password is required!");
        } elseif ($_POST['password'] !== $_POST['confirm_password']) {
            throw new Exception("Passwords do not match!");
        } else {
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
            file_put_contents('debug.log', "Hashed password: '$password'\n", FILE_APPEND);
        }

        // Validate terms
        if (empty($_POST['terms'])) {
            throw new Exception("You must agree to the terms and conditions!");
        }

        // Insert user
        $stmt = $pdo->prepare("INSERT INTO users (first_name, last_name, email, username, password, created_at, is_admin) VALUES (?, ?, ?, ?, ?, NOW(), 0)");
        $stmt->execute([$first_name, $last_name, $email, $username, $password]);

        file_put_contents('debug.log', "User registered successfully: '$username'\n", FILE_APPEND);

        $success_msg = "<p style='color: green; text-align: center; font-size: 14px;'>Registration successful! Redirecting to login...</p>";
        header("Refresh: 2; url=login.php");
        exit();
    } catch (Exception $e) {
        $error_msg = "<p style='color: red; text-align: center; font-size: 14px;'>" . $e->getMessage() . "</p>";
        file_put_contents('debug.log', "Registration error: " . $e->getMessage() . "\n", FILE_APPEND);
    } catch (PDOException $e) {
        $error_msg = "<p style='color: red; text-align: center; font-size: 14px;'>Database error: " . $e->getMessage() . "</p>";
        file_put_contents('debug.log', "Database error: " . $e->getMessage() . "\n", FILE_APPEND);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="../javaScript/scripts.js"></script>
</head>
<body>
    <div class="body">
        <div class="continer">
            <div class="card" id="card">
                <div class="div1">
                    <h2>REGISTER</h2>
                    <?php
                    if (isset($success_msg)) echo $success_msg;
                    if (isset($error_msg)) echo $error_msg;
                    ?>
                    <form method="post">
                        <input type="text" name="first_name" class="input" id="input1" placeholder="first name" required><br>
                        <input type="text" name="last_name" class="input" id="input2" placeholder="last name" required><br>
                        <input type="email" name="email" class="input" id="input3" placeholder="your email" required><br>
                        <input type="text" name="username" class="input" id="input4" placeholder="user name" required><br>
                        <input type="password" name="password" class="input" id="input5" placeholder="password" required><br>
                        <input type="password" name="confirm_password" class="input" id="input6" placeholder="confirm password" required><br>
                        <input type="checkbox" name="terms" required> I agree to the terms and conditions<br>
                        <button type="submit" class="submit-btn" name="signup" style="margin-top:3px;">Submit</button>
                    </form>
                    <a href="login.php">
                        <button type="button" class="btn" style="margin-top: -7px;">I've an account</button>
                    </a>
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