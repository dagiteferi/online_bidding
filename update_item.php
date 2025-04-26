<?php
require_once '../includes/db_connection.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

// Validate required fields
$required_fields = ['item_id', 'item_name', 'description', 'price', 'quantity'];
foreach ($required_fields as $field) {
    if (!isset($_POST[$field]) || empty($_POST[$field])) {
        echo json_encode(['success' => false, 'message' => "Missing required field: $field"]);
        exit;
    }
}

// Sanitize and validate input
$item_id = (int)$_POST['item_id'];
$item_name = sanitizeInput($_POST['item_name']);
$description = sanitizeInput($_POST['description']);
$price = (float)$_POST['price'];
$quantity = (int)$_POST['quantity'];
$close_time = isset($_POST['close_time']) ? $_POST['close_time'] : null;

try {
    $stmt = $conn->prepare("
        UPDATE items 
        SET item_name = ?, 
            description = ?, 
            price = ?, 
            quantity = ?, 
            close_time = ?
        WHERE id = ?
    ");

    $stmt->execute([
        $item_name,
        $description,
        $price,
        $quantity,
        $close_time,
        $item_id
    ]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'message' => 'No changes made or item not found']);
    }
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?> 