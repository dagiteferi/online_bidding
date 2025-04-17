<?php
// This page serves as the seller dashboard where sellers can manage their listings and offers.
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'seller') {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Seller Dashboard</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Seller Dashboard</h2>
    <nav>
        <a href="view_items.php?type=buy">View Items to Buy</a> |
        <a href="../index.php?logout=true">Logout</a>
    </nav>

    <h3>My Offers</h3>
    <?php
    $stmt = $pdo->prepare("SELECT o.*, i.item_name FROM offers o JOIN items i ON o.item_id = i.id WHERE o.user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    while ($offer = $stmt->fetch()) {
        echo "<p>Offer on {$offer['item_name']}: {$offer['offer_price']} (Qty: {$offer['quantity']}) - Status: {$offer['status']}</p>";
    }
    ?>
</body>
</html>