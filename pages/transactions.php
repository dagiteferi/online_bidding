<?php
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

// Accept an offer
if (isset($_GET['accept_offer'])) {
    $offer_id = $_GET['accept_offer'];
    $stmt = $pdo->prepare("SELECT * FROM offers WHERE id = ?");
    $stmt->execute([$offer_id]);
    $offer = $stmt->fetch();

    // Update offer status
    $stmt = $pdo->prepare("UPDATE offers SET status = 'accepted' WHERE id = ?");
    $stmt->execute([$offer_id]);

    // Update item status
    $stmt = $pdo->prepare("UPDATE items SET status = ? WHERE id = ?");
    $stmt->execute([$offer['item_id'], $offer['item_id'] == 'sell' ? 'sold' : 'purchased']);

    // Record transaction
    $stmt = $pdo->prepare("INSERT INTO transactions (item_id, offer_id, buyer_or_seller_id, final_price, quantity) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$offer['item_id'], $offer_id, $offer['user_id'], $offer['offer_price'], $offer['quantity']]);
}

// Reject an offer
if (isset($_GET['reject_offer'])) {
    $offer_id = $_GET['reject_offer'];
    $stmt = $pdo->prepare("UPDATE offers SET status = 'rejected' WHERE id = ?");
    $stmt->execute([$offer_id]);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transactions</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Transactions</h2>
    <?php
    $stmt = $pdo->query("SELECT t.*, i.item_name, u.username FROM transactions t JOIN items i ON t.item_id = i.id JOIN users u ON t.buyer_or_seller_id = u.id");
    while ($transaction = $stmt->fetch()) {
        echo "<p>Transaction on {$transaction['item_name']} with {$transaction['username']}: {$transaction['final_price']} (Qty: {$transaction['quantity']})</p>";
    }
    ?>
</body>
</html>