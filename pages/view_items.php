<?php
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$type = $_GET['type'] ?? 'sell';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Items</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Items to <?php echo ucfirst($type); ?></h2>
    <?php
    $stmt = $pdo->prepare("SELECT * FROM items WHERE type = ? AND status = 'available'");
    $stmt->execute([$type]);
    while ($item = $stmt->fetch()) {
        echo "<div>
                <h3>{$item['item_name']}</h3>
                <p>Description: {$item['description']}</p>
                <p>Price/Budget: {$item['price']}</p>
                <p>Quantity: {$item['quantity']}</p>
                <a href='submit_offer.php?item_id={$item['id']}'>Make Offer</a>
              </div><hr>";
    }
    ?>
</body>
</html>