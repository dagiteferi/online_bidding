<?php
// Start the session to manage user authentication
session_start();

// Include the database connection file
require_once '../config/db_connect.php';

// Redirect to login page if the user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Determine the type of items to display (default to 'sell')
$type = $_GET['type'] ?? 'sell';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Items</title>
    <!-- Link to the main stylesheet -->
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Items to <?php echo ucfirst($type); ?></h2>
    <?php
    // Prepare and execute the query to fetch available items of the specified type
    $stmt = $pdo->prepare("SELECT * FROM items WHERE type = ? AND status = 'available'");
    $stmt->execute([$type]);

    // Loop through the fetched items and display them
    while ($item = $stmt->fetch()) {
        echo "<div>
                <h3>{$item['item_name']}</h3>
                <p>Description: {$item['description']}</p>
                <p>Price/Budget: {$item['price']}</p>
                <p>Quantity: {$item['quantity']}</p>
                <a href='submit_offer.php?item_id={$item['id']}'>Make Offer</a>
            </div>";
    }
    ?>
</body>
</html>