<?php
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Check if user is admin
if (!isAdmin()) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Get POST data
$id = $_POST['id'] ?? 0;
$type = $_POST['type'] ?? '';
$title = $_POST['title'] ?? '';
$description = $_POST['description'] ?? '';
$price = $_POST['price'] ?? 0;
$status = $_POST['status'] ?? '';

if (!$id || !in_array($type, ['sale', 'request']) || !$title || !$description) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid parameters']);
    exit;
}

try {
    $table = $type === 'sale' ? 'items_for_sale' : 'requests';
    $priceField = $type === 'sale' ? 'price' : 'budget';
    
    $stmt = $pdo->prepare("UPDATE $table SET 
        title = ?, 
        description = ?, 
        $priceField = ?, 
        status = ? 
        WHERE id = ?");
        
    $stmt->execute([$title, $description, $price, $status, $id]);
    
    if ($stmt->rowCount() > 0) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
    } else {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'No changes made']);
    }
    
} catch (PDOException $e) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Database error']);
}
?> 