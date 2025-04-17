<?php
// This page allows users to create new listings for items they want to sell.
session_start();
require_once '../config/db_connect.php';

// Redirect if not logged in
if (!isset($_SESSION['user_id']) || $_SESSION['is_admin']) {
    header("Location: login.php");
    exit();
}

// Validate inputs and handle image upload
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $title = trim($_POST['title']);
        $description = trim($_POST['description']);
        $category = trim($_POST['category']);
        $starting_bid = floatval($_POST['starting_bid']);
        $end_date = $_POST['end_date'];
        $user_id = $_SESSION['user_id'];

        // Ensure all required fields are filled and valid
        if (empty($title) || empty($description) || empty($category) || $starting_bid <= 0 || empty($end_date)) {
            $error = "All fields are required, and starting bid must be positive.";
        } elseif (strtotime($end_date) <= time()) {
            $error = "End date must be in the future.";
        } else {
            // Handle image upload
            $image_path = null;
            if (isset($_FILES['image']) && $_FILES['image']['error'] == 0) {
                $allowed = ['jpg', 'jpeg', 'png'];
                $ext = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
                if (in_array(strtolower($ext), $allowed) && $_FILES['image']['size'] <= 5000000) { // 5MB max
                    $image_path = 'uploads/' . uniqid() . '.' . $ext;
                    move_uploaded_file($_FILES['image']['tmp_name'], '../' . $image_path);
                } else {
                    $error = "Invalid image format or size (max 5MB, JPG/PNG).";
                }
            }

            if (!$error) {
                // Insert item into the database
                $stmt = $pdo->prepare("INSERT INTO items (user_id, title, description, category, starting_bid, end_date, image, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')");
                $stmt->execute([$user_id, $title, $description, $category, $starting_bid, $end_date, $image_path]);

                $success = "Listing created successfully! Awaiting admin approval.";
                header("Refresh: 2; url=user_dashboard.php");
            }
        }
    } catch (PDOException $e) {
        $error = "Error creating listing: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Listing</title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="../javaScript/scripts.js"></script>
</head>
<body>
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
                <a href="user_dashboard.php">Dashboard</a>
                <a href="../logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="body">
        <div class="continer">
            <div class="card" id="card">
                <div class="div1">
                    <h2>Create New Listing</h2>
                    <?php
                    if (isset($error)) echo "<p style='color: red; text-align: center;'>$error</p>";
                    if (isset($success)) echo "<p style='color: green; text-align: center;'>$success</p>";
                    ?>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="text" name="title" class="input" id="input1" placeholder="Item Title" required />
                        <textarea name="description" class="input" id="input2" placeholder="Description" rows="4" required></textarea>
                        <select name="category" class="input" id="input3" required>
                            <option value="">Select Category</option>
                            <option value="Electronics">Electronics</option>
                            <option value="Collectibles">Collectibles</option>
                            <option value="Fashion">Fashion</option>
                            <option value="Home">Home</option>
                        </select>
                        <input type="number" name="starting_bid" class="input" id="input4" placeholder="Starting Bid ($)" step="0.01" required />
                        <input type="datetime-local" name="end_date" class="input" id="input5" required />
                        <input type="file" name="image" class="input" id="input6" accept="image/jpeg,image/png" />
                        <button type="submit" class="submit-btn">Submit</button>
                    </form>
                    <a href="user_dashboard.php">
                        <button type="button" class="btn" style="margin-top: -7px;">Back to Dashboard</button>
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