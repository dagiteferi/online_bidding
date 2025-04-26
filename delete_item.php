<?php
require_once '../includes/db_connection.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

if (!isset($_POST['item_id']) || !is_numeric($_POST['item_id'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid item ID']);
    exit;
}

$item_id = (int)$_POST['item_id'];

try {
    // Start transaction
    $conn->beginTransaction();

    // First, delete any related records (e.g., bids, offers, etc.)
    $stmt = $conn->prepare("DELETE FROM bids WHERE item_id = ?");
    $stmt->execute([$item_id]);

    $stmt = $conn->prepare("DELETE FROM offers WHERE item_id = ?");
    $stmt->execute([$item_id]);

    // Then delete the item
    $stmt = $conn->prepare("DELETE FROM items WHERE id = ?");
    $stmt->execute([$item_id]);

    // Commit transaction
    $conn->commit();

    echo json_encode(['success' => true]);
} catch (PDOException $e) {
    // Rollback transaction on error
    $conn->rollBack();
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?> 