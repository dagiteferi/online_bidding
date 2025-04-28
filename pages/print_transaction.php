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
            br.max_price AS max_price_buy,
            o.status AS offer_status
        FROM transactions t 
        LEFT JOIN items i ON t.item_id = i.id 
        LEFT JOIN buy_requests br ON t.request_id = br.id 
        JOIN users ub ON t.buyer_or_seller_id = ub.id 
        LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id)
        LEFT JOIN offers o ON t.offer_id = o.id
        WHERE t.id = :id 
        AND (i.posted_by = :user_id1 OR br.user_id = :user_id2)
        AND o.status IN ('accepted', 'completed')
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
    
    $item_name = $transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A';
    $type = $transaction['item_id'] ? 'Sell' : 'Buy';
    $total_amount = $transaction['final_price'] * $transaction['quantity'];
    
    // Set headers for HTML output
    header('Content-Type: text/html; charset=utf-8');
    
    // Generate HTML content with proper styling for printing
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Transaction Receipt #<?php echo str_pad($transaction_id, 6, '0', STR_PAD_LEFT); ?></title>
        <style>
            @media print {
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                }
                .receipt {
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    border: 1px solid #ddd;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #333;
                }
                .details {
                    margin-bottom: 20px;
                }
                .detail-row {
                    margin-bottom: 10px;
                    display: flex;
                    justify-content: space-between;
                    padding: 5px 0;
                    border-bottom: 1px solid #eee;
                }
                .label {
                    font-weight: bold;
                    width: 40%;
                }
                .value {
                    width: 60%;
                    text-align: right;
                }
                .footer {
                    margin-top: 30px;
                    text-align: center;
                    padding-top: 20px;
                    border-top: 2px solid #333;
                }
                .signature {
                    margin-top: 50px;
                }
                .signature-line {
                    border-top: 1px solid #000;
                    width: 200px;
                    margin: 20px auto;
                }
                .company-logo {
                    max-width: 200px;
                    margin-bottom: 20px;
                }
                .transaction-id {
                    font-size: 1.2em;
                    color: #666;
                }
                .total-amount {
                    font-size: 1.5em;
                    font-weight: bold;
                    color: #2c3e50;
                    margin-top: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="receipt">
            <div class="header">
                <h1>Transaction Receipt</h1>
                <p class="transaction-id">Transaction ID: #<?php echo str_pad($transaction_id, 6, '0', STR_PAD_LEFT); ?></p>
                <p>Date: <?php echo date('M j, Y g:i A', strtotime($transaction['created_at'])); ?></p>
            </div>
            
            <div class="details">
                <div class="detail-row">
                    <span class="label">Item Name:</span>
                    <span class="value"><?php echo htmlspecialchars($item_name); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Transaction Type:</span>
                    <span class="value"><?php echo htmlspecialchars($type); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Buyer:</span>
                    <span class="value"><?php echo htmlspecialchars($transaction['buyer']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Seller:</span>
                    <span class="value"><?php echo htmlspecialchars($transaction['seller'] ?? 'N/A'); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Final Price:</span>
                    <span class="value">$<?php echo number_format($transaction['final_price'], 2); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Quantity:</span>
                    <span class="value"><?php echo htmlspecialchars($transaction['quantity']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Total Amount:</span>
                    <span class="value total-amount">$<?php echo number_format($total_amount, 2); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Status:</span>
                    <span class="value"><?php echo ucfirst($transaction['offer_status'] ?? 'Completed'); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Description:</span>
                    <span class="value"><?php echo htmlspecialchars($transaction['description_sell'] ?? $transaction['description_buy'] ?? 'N/A'); ?></span>
                </div>
            </div>
            
            <div class="footer">
                <div class="signature">
                    <div class="signature-line"></div>
                    <p>Authorized Signature</p>
                </div>
                <p>Thank you for your business!</p>
            </div>
        </div>
        
        <script>
            // Automatically trigger print when the page loads
            window.onload = function() {
                window.print();
            };
        </script>
    </body>
    </html>
    <?php
    
} catch (PDOException $e) {
    header('HTTP/1.1 500 Internal Server Error');
    exit('Database error: ' . $e->getMessage());
} 