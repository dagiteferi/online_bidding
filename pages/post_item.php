<?php
// This page allows users to post new items for sale.
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

$type = $_GET['type'] ?? 'sell';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $supplier_name = $_POST['supplier_name'] ?? null;
    $item_name = $_POST['item_name'];
    $description = $_POST['description'];
    $price = $_POST['price'];
    $quantity = $_POST['quantity'];

    $stmt = $pdo->prepare("INSERT INTO items (type, supplier_name, item_name, description, price, quantity) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$type, $supplier_name, $item_name, $description, $price, $quantity]);

    header("Location: admin_dashboard.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Post Item</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <h2>Post Item to <?php echo ucfirst($type); ?></h2>
    <form method="POST">
        <?php if ($type == 'sell') { ?>
            <label>Supplier Name:</label><br>
            <input type="text" name="supplier_name" required><br>
        <?php } ?>
        <label>Item Name:</label><br>
        <input type="text" name="item_name" required><br>
        <label>Description:</label><br>
        <textarea name="description" required></textarea><br>
        <label><?php echo $type == 'sell' ? 'Price' : 'Max Budget'; ?>:</label><br>
        <input type="number" name="price" step="0.01" required><br>
        <label>Quantity:</label><br>
        <input type="number" name="quantity" required><br>
        <button type="submit">Submit</button>
    </form>
</body>
</html>