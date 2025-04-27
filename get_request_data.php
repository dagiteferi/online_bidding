<?php
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Check if user is admin
if (!isAdmin()) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$id = $_GET['id'] ?? 0;
$type = $_GET['type'] ?? '';

if (!$id || !in_array($type, ['sale', 'request'])) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid parameters']);
    exit;
}

try {
    $table = $type === 'sale' ? 'items_for_sale' : 'requests';
    $stmt = $pdo->prepare("SELECT * FROM $table WHERE id = ?");
    $stmt->execute([$id]);
    $data = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$data) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Record not found']);
        exit;
    }
    
    // Format the data for the form
    $response = [
        'title' => $data['title'],
        'description' => $data['description'],
        'price' => $type === 'sale' ? $data['price'] : $data['budget'],
        'status' => $data['status']
    ];
    
    header('Content-Type: application/json');
    echo json_encode($response);
    
} catch (PDOException $e) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Database error']);
}
?> 