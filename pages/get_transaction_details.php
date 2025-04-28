<?php
session_start();
require_once '../config/db_connect.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access denied');
}

if (!isset($_GET['id'])) {
    header('HTTP/1.1 400 Bad Request');
    exit('Transaction ID is required');
}

$transaction_id = intval($_GET['id']);

try {
    $stmt = $pdo->prepare("
        SELECT t.*, 
            i.item_name AS item_name_sell, 
            br.item_name AS item_name_buy, 
            ub.username AS buyer, 
            us.username AS seller,
            i.supplier_name AS supplier_name_sell,
            i.description AS description_sell,
            br.description AS description_buy,
            i.price AS original_price_sell,
            br.max_price AS max_price_buy
        FROM transactions t 
        LEFT JOIN items i ON t.item_id = i.id 
        LEFT JOIN buy_requests br ON t.request_id = br.id 
        JOIN users ub ON t.buyer_or_seller_id = ub.id 
        LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id) 
        WHERE t.id = :id AND (i.posted_by = :user_id1 OR br.user_id = :user_id2)
    ");
    
    $stmt->execute([
        ':id' => $transaction_id,
        ':user_id1' => $_SESSION['user_id'],
        ':user_id2' => $_SESSION['user_id']
    ]);
    
    $transaction = $stmt->fetch();
    
    if (!$transaction) {
        header('HTTP/1.1 404 Not Found');
        exit('Transaction not found');
    }
    
    $response = [
        'id' => $transaction['id'],
        'item_name' => $transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A',
        'type' => $transaction['item_id'] ? 'Sell' : 'Buy',
        'buyer' => $transaction['buyer'],
        'seller' => $transaction['seller'] ?? 'N/A',
        'final_price' => number_format($transaction['final_price'], 2),
        'quantity' => $transaction['quantity'],
        'total_amount' => number_format($transaction['final_price'] * $transaction['quantity'], 2),
        'date' => date('M j, Y g:i A', strtotime($transaction['created_at'])),
        'status' => ucfirst($transaction['status'] ?? 'Completed'),
        'supplier' => $transaction['supplier_name_sell'] ?? 'N/A',
        'description' => $transaction['description_sell'] ?? $transaction['description_buy'] ?? 'N/A',
        'original_price' => number_format($transaction['item_id'] ? ($transaction['original_price_sell'] ?? 0) : ($transaction['max_price_buy'] ?? 0), 2)
    ];
    
    header('Content-Type: application/json');
    echo json_encode($response);
    
} catch (PDOException $e) {
    header('HTTP/1.1 500 Internal Server Error');
    exit('Database error: ' . $e->getMessage());
} 