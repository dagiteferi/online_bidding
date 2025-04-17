<?php
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id']) || !isset($_GET['item_id'])) {
    header("Location: login.php");
    exit();
}

$item_id = $_GET['item_id'];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $offer_price = $_POST['offer_price'];
    $quantity = $_POST['quantity'];

    $stmt = $pdo->prepare("INSERT INTO offers (item_id, user_id, offer_price, quantity) VALUES (?, ?, ?, ?)");
    $stmt->execute([$item_id, $_SESSION['user_id'], $offer_price, $quantity]);

    header("Location: " . ($_SESSION['role'] == 'buyer' ? 'buyer_dashboard.php' : 'seller_dashboard.php'));
    exit();
}

$stmt = $pdo->prepare("SELECT * FROM items WHERE id = ?");
$stmt->execute([$item_id]);
$item = $stmt->fetch();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Submit Offer</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Make Offer on <?php echo $item['item_name']; ?></h2>
    <form method="POST">
        <label>Offer Price:</label><br>
        <input type="number" name="offer_price" step="0.01" required><br>
        <label>Quantity:</label><br>
        <input type="number" name="quantity" required><br>
        <button type="submit">Submit Offer</button>
    </form>
</body>
</html>