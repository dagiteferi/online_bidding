<?php
ob_start();
session_start();
require_once '../config/db_connect.php';

// Check if user is logged in and is not an admin
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin']) {
    header("Location: ../login.php");
    exit();
}

// Validate user_id against the users table
try {
    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE id = ? AND is_admin = 0");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    if (!$user) {
        session_destroy();
        header("Location: ../login.php?error=invalid_user");
        exit();
    }
    $_SESSION['username'] = $user['username'];
    error_log("Logged-in user_id: {$_SESSION['user_id']}, username: {$_SESSION['username']}");
} catch (PDOException $e) {
    error_log("User validation failed: " . $e->getMessage());
    session_destroy();
    header("Location: ../login.php?error=database_error");
    exit();
}

// Handle offer submission
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit_offer'])) {
    $item_id = isset($_POST['item_id']) && $_POST['item_id'] !== '' ? intval($_POST['item_id']) : null;
    $request_id = isset($_POST['request_id']) && $_POST['request_id'] !== '' ? intval($_POST['request_id']) : null;
    $offer_type = trim($_POST['offer_type'] ?? '');
    $offered_price = trim($_POST['offered_price'] ?? '');
    $quantity = trim($_POST['quantity'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $buyer_name = trim($_POST['buyer_name'] ?? '');

    if (empty($buyer_name)) {
        $error_msg = "Please enter your buyer name.";
    } elseif (empty($offered_price) || !is_numeric($offered_price) || $offered_price <= 0) {
        $error_msg = "Please enter a valid offered price (greater than 0).";
    } elseif (empty($quantity) || !is_numeric($quantity) || $quantity <= 0) {
        $error_msg = "Please enter a valid quantity (greater than 0).";
    } elseif ($item_id === null && $request_id === null) {
        $error_msg = "Invalid item or request ID.";
    } elseif (!in_array($offer_type, ['buy', 'sell'])) {
        $error_msg = "Invalid offer type.";
    } else {
        try {
            $pdo->beginTransaction();

            if ($item_id !== null) {
                $stmt = $pdo->prepare("SELECT status FROM items WHERE id = ?");
                $stmt->execute([$item_id]);
                $item = $stmt->fetch();

                if (!$item) {
                    $error_msg = "Item not found.";
                } elseif ($item['status'] != 'open') {
                    $error_msg = "This item is no longer available for offers.";
                } else {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM offers WHERE item_id = ? AND user_id = ? AND request_id IS NULL");
                    $stmt->execute([$item_id, $_SESSION['user_id']]);
                    if ($stmt->fetchColumn() > 0) {
                        $error_msg = "You have already submitted an offer for this item.";
                    }
                }
            } elseif ($request_id !== null) {
                $stmt = $pdo->prepare("SELECT status FROM buy_requests WHERE id = ?");
                $stmt->execute([$request_id]);
                $request = $stmt->fetch();

                if (!$request) {
                    $error_msg = "Buy request not found.";
                } elseif ($request['status'] != 'open') {
                    $error_msg = "This buy request is no longer available for offers.";
                } else {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM offers WHERE request_id = ? AND user_id = ? AND item_id IS NULL");
                    $stmt->execute([$request_id, $_SESSION['user_id']]);
                    if ($stmt->fetchColumn() > 0) {
                        $error_msg = "You have already submitted an offer for this buy request.";
                    }
                }
            }

            if (!isset($error_msg)) {
                $description = empty($description) ? NULL : $description;
                $stmt = $pdo->prepare("INSERT INTO offers (item_id, request_id, user_id, offer_type, offered_price, quantity, description, buyer_name, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())");
                $result = $stmt->execute([$item_id, $request_id, $_SESSION['user_id'], $offer_type, $offered_price, $quantity, $description, $buyer_name]);
                if ($result) {
                    $offer_id = $pdo->lastInsertId();
                    $success_msg = "Offer submitted successfully!";
                    error_log("Offer inserted - offer_id: $offer_id, item_id: $item_id, request_id: $request_id, user_id: {$_SESSION['user_id']}, offer_type: $offer_type, price: $offered_price, quantity: $quantity, buyer_name: $buyer_name");
                    $pdo->commit();
                } else {
                    $error_msg = "Failed to submit offer. Please try again.";
                    $pdo->rollBack();
                }
            } else {
                $pdo->rollBack();
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            $error_msg = "Database error: " . $e->getMessage();
            error_log("Offer submission failed: " . $e->getMessage());
        }
    }

    if (isset($success_msg)) {
        // Check if dashboard.php exists
        if (file_exists(__DIR__ . '/dashboard.php')) {
            header("Location: dashboard.php?success=" . urlencode($success_msg));
            exit();
        } else {
            $error_msg = "Error: dashboard.php not found in " . __DIR__;
            error_log($error_msg);
        }
    }
}

// Handle offer editing
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['edit_offer'])) {
    $offer_id = isset($_POST['offer_id']) ? intval($_POST['offer_id']) : 0;
    $offered_price = trim($_POST['offered_price'] ?? '');
    $quantity = trim($_POST['quantity'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $buyer_name = trim($_POST['buyer_name'] ?? '');

    if (empty($buyer_name)) {
        $error_msg = "Please enter your buyer name.";
    } elseif (empty($offered_price) || !is_numeric($offered_price) || $offered_price <= 0) {
        $error_msg = "Please enter a valid offered price (greater than 0).";
    } elseif (empty($quantity) || !is_numeric($quantity) || $quantity <= 0) {
        $error_msg = "Please enter a valid quantity (greater than 0).";
    } elseif ($offer_id <= 0) {
        $error_msg = "Invalid offer ID.";
    } else {
        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare("SELECT status, item_id, request_id FROM offers WHERE id = ? AND user_id = ?");
            $stmt->execute([$offer_id, $_SESSION['user_id']]);
            $offer = $stmt->fetch();

            if (!$offer) {
                $error_msg = "Offer not found or you don't have permission to edit it.";
            } elseif ($offer['status'] != 'pending') {
                $error_msg = "This offer can no longer be edited as it is " . htmlspecialchars($offer['status']) . ".";
            } else {
                if ($offer['item_id']) {
                    $stmt = $pdo->prepare("SELECT status FROM items WHERE id = ?");
                    $stmt->execute([$offer['item_id']]);
                    $item = $stmt->fetch();
                    if (!$item || $item['status'] != 'open') {
                        $error_msg = "The associated item is no longer available for offers.";
                    }
                } elseif ($offer['request_id']) {
                    $stmt = $pdo->prepare("SELECT status FROM buy_requests WHERE id = ?");
                    $stmt->execute([$offer['request_id']]);
                    $request = $stmt->fetch();
                    if (!$request || $request['status'] != 'open') {
                        $error_msg = "The associated buy request is no longer available for offers.";
                    }
                }

                if (!isset($error_msg)) {
                    $description = empty($description) ? NULL : $description;
                    $stmt = $pdo->prepare("UPDATE offers SET offered_price = ?, quantity = ?, description = ?, buyer_name = ? WHERE id = ? AND user_id = ?");
                    $stmt->execute([$offered_price, $quantity, $description, $buyer_name, $offer_id, $_SESSION['user_id']]);
                    $success_msg = "Offer updated successfully!";
                    error_log("Offer updated - offer_id: $offer_id, user_id: {$_SESSION['user_id']}, price: $offered_price, quantity: $quantity, buyer_name: $buyer_name");
                    $pdo->commit();
                    if (file_exists(__DIR__ . '/dashboard.php')) {
                        header("Location: dashboard.php?success=" . urlencode($success_msg));
                        exit();
                    } else {
                        $error_msg = "Error: dashboard.php not found in " . __DIR__;
                        error_log($error_msg);
                    }
                } else {
                    $pdo->rollBack();
                }
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            $error_msg = "Database error: " . $e->getMessage();
            error_log("Offer update failed: " . $e->getMessage());
        }
    }
}

// Fetch all admin-posted items
try {
    $stmt = $pdo->prepare("SELECT i.id, i.item_name AS title, i.description, i.price, 'for_sale' AS item_type, i.status, i.created_at, i.image, u.username AS admin_name 
                           FROM items i 
                           JOIN users u ON i.posted_by = u.id 
                           WHERE u.is_admin = 1");
    $stmt->execute();
    $items = $stmt->fetchAll();
} catch (PDOException $e) {
    $error_msg = "Error fetching items: " . $e->getMessage();
    error_log("Items fetch failed: " . $e->getMessage());
    $items = [];
}

// Fetch all admin-posted buy requests
try {
    $stmt = $pdo->prepare("SELECT br.id, br.item_name, br.description, br.max_price, br.quantity, br.status, br.created_at, br.image, u.username AS admin_name 
                           FROM buy_requests br 
                           JOIN users u ON br.user_id = u.id 
                           WHERE u.is_admin = 1");
    $stmt->execute();
    $buy_requests = $stmt->fetchAll();
} catch (PDOException $e) {
    $error_msg = "Error fetching buy requests: " . $e->getMessage();
    error_log("Buy requests fetch failed: " . $e->getMessage());
    $buy_requests = [];
}

// Fetch user's offers
$user_offers = [];
try {
    $stmt = $pdo->prepare("SELECT o.id, o.item_id, o.request_id, o.offer_type, o.offered_price, o.quantity, o.description, o.buyer_name, o.status, o.created_at, 
                           COALESCE(i.item_name, br.item_name) AS item_name 
                           FROM offers o 
                           LEFT JOIN items i ON o.item_id = i.id 
                           LEFT JOIN buy_requests br ON o.request_id = br.id 
                           WHERE o.user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user_offers = $stmt->fetchAll();
    error_log("Fetched " . count($user_offers) . " offers for user_id: {$_SESSION['user_id']}");
} catch (PDOException $e) {
    $error_msg = "Error fetching offers: " . $e->getMessage();
    error_log("Offer fetch failed: " . $e->getMessage());
    $user_offers = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard - Offer System</title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #48dbfb;
            --secondary-color: #353b48;
            --text-color: #fff;
            --dark-text: #111;
            --light-bg: #f8f9fa;
        }
        
        body {
            font-family: 'Ubuntu', sans-serif;
            color: var(--dark-text);
            background-color: var(--light-bg);
            padding-top: 80px;
        }
        
        .dashboard-container {
            max-width: 1300px;
            margin: 0 auto;
            padding: 0 40px;
        }
        
        .welcome-banner {
            background: linear-gradient(110deg, var(--primary-color) 60%, #98e4f5 60%);
            color: var(--text-color);
            padding: 40px;
            border-radius: 10px;
            margin: 30px 0;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .welcome-banner h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .welcome-banner .btn-view-offers {
            background-color: var(--text-color);
            color: var(--secondary-color);
            padding: 10px 20px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 500;
            margin-top: 15px;
            display: inline-block;
            transition: background-color 0.3s;
        }
        
        .welcome-banner .btn-view-offers:hover {
            background-color: #e0e0e0;
        }
        
        .section-title {
            text-align: center;
            margin: 60px 0 30px;
            position: relative;
            font-size: 26px;
            color: var(--dark-text);
        }
        
        .section-title::after {
            content: '';
            width: 60px;
            height: 4px;
            background-color: var(--primary-color);
            position: absolute;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
        }
        
        .items-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 25px;
            margin-bottom: 50px;
        }
        
        .item-card {
            background: #fff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
        }
        
        .item-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        
        .item-img-container {
            height: 200px;
            overflow: hidden;
            background-color: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .item-img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .no-image {
            color: #95a5a6;
            font-size: 14px;
        }
        
        .item-body {
            padding: 20px;
        }
        
        .item-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--secondary-color);
        }
        
        .item-price {
            color: var(--primary-color);
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 15px;
        }
        
        .item-desc {
            color: #666;
            font-size: 14px;
            margin-bottom: 15px;
        }
        
        .item-admin {
            color: #777;
            font-size: 13px;
            margin-bottom: 15px;
        }
        
        .item-status {
            position: absolute;
            top: 15px;
            right: 15px;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .status-open {
            background-color: #2ecc71;
            color: white;
        }
        
        .status-closed {
            background-color: #e74c3c;
            color: white;
        }
        
        .btn-offer {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 50px;
            width: 100%;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .btn-offer:hover {
            background-color: #3aa8d8;
        }
        
        .btn-disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        
        .offers-table-container {
            background: #fff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            margin-bottom: 50px;
            overflow-x: auto;
        }
        
        .offers-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .offers-table th {
            background-color: var(--primary-color);
            color: white;
            padding: 15px;
            text-align: left;
        }
        
        .offers-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        .offers-table tr:hover {
            background-color: rgba(72, 219, 251, 0.05);
        }
        
        .offer-status {
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .status-pending {
            background-color: #f39c12;
            color: white;
        }
        
        .status-accepted {
            background-color: #2ecc71;
            color: white;
        }
        
        .status-rejected {
            background-color: #e74c3c;
            color: white;
        }
        
        .status-closed {
            background-color: #95a5a6;
            color: white;
        }
        
        .btn-edit {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 5px 15px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            transition: background-color 0.3s;
        }
        
        .btn-edit:hover {
            background-color: #2980b9;
        }
        
        .btn-edit:disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        
        .alert-message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 25px;
            text-align: center;
            font-weight: 500;
        }
        
        .alert-success {
            background-color: rgba(46, 204, 113, 0.2);
            color: #27ae60;
        }
        
        .alert-error {
            background-color: rgba(231, 76, 60, 0.2);
            color: #c0392b;
        }
        
        .empty-state {
            text-align: center;
            padding: 50px 20px;
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            margin-bottom: 50px;
        }
        
        .empty-state i {
            font-size: 50px;
            color: #95a5a6;
            margin-bottom: 20px;
        }
        
        .empty-state h3 {
            color: var(--secondary-color);
            margin-bottom: 10px;
        }
        
        .empty-state p {
            color: #666;
        }
        
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background: #fff;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 5px 25px rgba(0,0,0,0.2);
            position: relative;
        }
        
        .modal-header {
            margin-bottom: 20px;
        }
        
        .modal-header h3 {
            color: var(--secondary-color);
            font-size: 1.5rem;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .form-control-textarea {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            resize: vertical;
        }
        
        .input-group {
            display: flex;
            align-items: center;
        }
        
        .input-group-text {
            padding: 10px;
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-right: none;
            border-radius: 5px 0 0 5px;
        }
        
        .input-group .form-control {
            border-radius: 0 5px 5px 0;
        }
        
        .btn-submit {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            font-size: 16px;
            transition: background-color 0.3s;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .btn-submit:hover {
            background-color: #3aa8d8;
        }
        
        .btn-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            position: absolute;
            top: 15px;
            right: 15px;
            cursor: pointer;
            color: #777;
        }
        
        @media (max-width: 768px) {
            .dashboard-container {
                padding: 0 20px;
            }
            
            .items-grid {
                grid-template-columns: 1fr;
            }
            
            .welcome-banner h1 {
                font-size: 2rem;
            }
            
            .offers-table th, .offers-table td {
                padding: 8px;
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="inner-width">
            <a href="../index.php" class="logo"></a>
            <button class="menu-toggler">
                <span></span>
                <span></span>
                <span></span>
            </button>
            <div class="navbar-menu">
                <a href="../index.php">Home</a>
                <a href="../index.php#about">About</a>
                <a href="../index.php#contact">Contact</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="dashboard-container">
        <div class="welcome-banner">
            <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?>!</h1>
            <p>Manage your offers, browse available items, and respond to admin buy requests</p>
            <a href="#your-offers" class="btn-view-offers"><i class="fas fa-handshake"></i> View Your Offers</a>
        </div>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="alert-message alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($_GET['success']); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($error_msg)): ?>
            <div class="alert-message alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error_msg); ?>
            </div>
        <?php endif; ?>
        
        <h2 class="section-title"><i class="fas fa-box-open"></i> Available Items</h2>
        
        <?php if (empty($items)): ?>
            <div class="empty-state">
                <i class="fas fa-box-open"></i>
                <h3>No Items Available</h3>
                <p>There are currently no items posted by admins. Please check back later.</p>
            </div>
        <?php else: ?>
            <div class="items-grid">
                <?php foreach ($items as $item): ?>
                    <div class="item-card">
                        <div class="item-img-container">
                            <?php if (!empty($item['image'])): ?>
                                <img src="../<?php echo htmlspecialchars($item['image']); ?>" class="item-img" alt="<?php echo htmlspecialchars($item['title']); ?>">
                            <?php else: ?>
                                <div class="no-image">
                                    <i class="fas fa-image fa-3x"></i>
                                    <p>No Image Available</p>
                                </div>
                            <?php endif; ?>
                            <span class="item-status <?php echo $item['status'] == 'open' ? 'status-open' : 'status-closed'; ?>">
                                <?php echo htmlspecialchars($item['status']); ?>
                            </span>
                        </div>
                        <div class="item-body">
                            <h3 class="item-title"><?php echo htmlspecialchars($item['title']); ?></h3>
                            <div class="item-price">$<?php echo number_format($item['price'], 2); ?></div>
                            <p class="item-desc"><?php echo htmlspecialchars($item['description'] ?? 'No description provided'); ?></p>
                            <p class="item-admin"><i class="fas fa-user-tie"></i> <?php echo htmlspecialchars($item['admin_name']); ?></p>
                            
                            <?php if ($item['status'] == 'open'): ?>
                                <button class="btn-offer" onclick="openOfferModal(<?php echo $item['id']; ?>, null, '<?php echo $item['item_type'] == 'for_sale' ? 'buy' : 'sell'; ?>', '<?php echo htmlspecialchars($item['title']); ?>')">
                                    <i class="fas fa-handshake"></i> Make Offer
                                </button>
                            <?php else: ?>
                                <button class="btn-offer btn-disabled" disabled>
                                    <i class="fas fa-lock"></i> Closed
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <h2 class="section-title"><i class="fas fa-hand-holding-usd"></i> Purchase Inquiries</h2>
        
        <?php if (empty($buy_requests)): ?>
            <div class="empty-state">
                <i class="fas fa-hand-holding-usd"></i>
                <h3>No Buy Requests Available</h3>
                <p>There are currently no buy requests posted by admins. Please check back later.</p>
            </div>
        <?php else: ?>
            <div class="items-grid">
                <?php foreach ($buy_requests as $request): ?>
                    <div class="item-card">
                        <div class="item-img-container">
                            <?php if (!empty($request['image'])): ?>
                                <img src="../<?php echo htmlspecialchars($request['image']); ?>" class="item-img" alt="<?php echo htmlspecialchars($request['item_name']); ?>">
                            <?php else: ?>
                                <div class="no-image">
                                    <i class="fas fa-image fa-3x"></i>
                                    <p>No Image Available</p>
                                </div>
                            <?php endif; ?>
                            <span class="item-status <?php echo $request['status'] == 'open' ? 'status-open' : 'status-closed'; ?>">
                                <?php echo htmlspecialchars($request['status']); ?>
                            </span>
                        </div>
                        <div class="item-body">
                            <h3 class="item-title"><?php echo htmlspecialchars($request['item_name']); ?></h3>
                            <div class="item-price">Max Price: $<?php echo number_format($request['max_price'], 2); ?></div>
                            <p class="item-desc"><?php echo htmlspecialchars($request['description'] ?? 'No description provided'); ?></p>
                            <p class="item-admin"><i class="fas fa-user-tie"></i> <?php echo htmlspecialchars($request['admin_name']); ?> | Qty: <?php echo htmlspecialchars($request['quantity']); ?></p>
                            
                            <?php if ($request['status'] == 'open'): ?>
                                <button class="btn-offer" onclick="openOfferModal(null, <?php echo $request['id']; ?>, 'sell', '<?php echo htmlspecialchars($request['item_name']); ?>')">
                                    <i class="fas fa-handshake"></i> Make Offer
                                </button>
                            <?php else: ?>
                                <button class="btn-offer btn-disabled" disabled>
                                    <i class="fas fa-lock"></i> Closed
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <h2 class="section-title" id="your-offers"><i class="fas fa-handshake"></i> Your Offers (<?php echo count($user_offers); ?>)</h2>
        
        <?php if (empty($user_offers)): ?>
            <div class="empty-state">
                <i class="fas fa-handshake"></i>
                <h3>No Offers Yet</h3>
                <p>You haven't made any offers yet. Browse the available items or buy requests above to get started.</p>
            </div>
        <?php else: ?>
            <div class="offers-table-container">
                <table class="offers-table">
                    <thead>
                        <tr>
                            <th>Item/Request</th>
                            <th>Buyer Name</th>
                            <th>Type</th>
                            <th>Your Price</th>
                            <th>Qty</th>
                            <th>Description</th>
                            <th>Status</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($user_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'] ?? 'Unknown'); ?></td>
                                <td><?php echo htmlspecialchars($offer['buyer_name'] ?? 'N/A'); ?></td>
                                <td><?php echo ucfirst(htmlspecialchars($offer['offer_type'] ?? 'Unknown')); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'] ?? 0, 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'] ?? 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($offer['description'] ?? 'No description provided'); ?></td>
                                <td>
                                    <span class="offer-status 
                                        <?php 
                                        $status = strtolower($offer['status'] ?? 'pending');
                                        if ($status == 'pending') echo 'status-pending';
                                        elseif ($status == 'accepted') echo 'status-accepted';
                                        elseif ($status == 'rejected') echo 'status-rejected';
                                        else echo 'status-closed';
                                        ?>">
                                        <?php echo htmlspecialchars(ucfirst($offer['status'] ?? 'Pending')); ?>
                                    </span>
                                </td>
                                <td><?php echo date('M j, Y', strtotime($offer['created_at'] ?? 'now')); ?></td>
                                <td>
                                    <button class="btn-edit" 
                                            onclick="openEditModal(<?php echo $offer['id']; ?>, '<?php echo htmlspecialchars($offer['item_name']); ?>', '<?php echo htmlspecialchars($offer['buyer_name']); ?>', <?php echo $offer['offered_price']; ?>, <?php echo $offer['quantity']; ?>, '<?php echo htmlspecialchars($offer['description'] ?? ''); ?>')"
                                            <?php echo $offer['status'] != 'pending' ? 'disabled' : ''; ?>>
                                        <i class="fas fa-edit"></i> Edit
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <div class="modal-overlay" id="offerModal">
        <div class="modal-content">
            <button class="btn-close" onclick="closeModal('offerModal')">×</button>
            <div class="modal-header">
                <h3 id="modalTitle">Make Offer</h3>
            </div>
            <form method="POST" id="offerForm">
                <input type="hidden" name="item_id" id="modalItemId">
                <input type="hidden" name="request_id" id="modalRequestId">
                <input type="hidden" name="offer_type" id="modalOfferType">
                
                <div class="form-group">
                    <label for="buyer_name">Buyer Name</label>
                    <input type="text" class="form-control" name="buyer_name" id="buyer_name" value="<?php echo htmlspecialchars($_SESSION['username'] ?? ''); ?>" required>
                </div>
                
                <div class="form-group">
                    <label for="offered_price">Your Offer Price</label>
                    <div class="input-group">
                        <span class="input-group-text">$</span>
                        <input type="number" class="form-control" name="offered_price" id="offered_price" placeholder="0.00" step="0.01" min="0.01" required>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="quantity">Quantity</label>
                    <input type="number" class="form-control" name="quantity" id="quantity" placeholder="1" min="1" required>
                </div>
                
                <div class="form-group">
                    <label for="description">Offer Description (Optional)</label>
                    <textarea class="form-control-textarea" name="description" id="description" rows="3" placeholder="Add any details about your offer (e.g., condition, delivery terms)"></textarea>
                </div>
                
                <div class="form-group">
                    <button type="submit" name="submit_offer" class="btn-submit">
                        <i class="fas fa-paper-plane"></i> Submit Offer
                    </button>
                </div>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="editOfferModal">
        <div class="modal-content">
            <button class="btn-close" onclick="closeModal('editOfferModal')">×</button>
            <div class="modal-header">
                <h3 id="editModalTitle">Edit Offer</h3>
            </div>
            <form method="POST" id="editOfferForm">
                <input type="hidden" name="offer_id" id="editModalOfferId">
                
                <div class="form-group">
                    <label for="edit_buyer_name">Buyer Name</label>
                    <input type="text" class="form-control" name="buyer_name" id="edit_buyer_name" required>
                </div>
                
                <div class="form-group">
                    <label for="edit_offered_price">Your Offer Price</label>
                    <div class="input-group">
                        <span class="input-group-text">$</span>
                        <input type="number" class="form-control" name="offered_price" id="edit_offered_price" step="0.01" min="0.01" required>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="edit_quantity">Quantity</label>
                    <input type="number" class="form-control" name="quantity" id="edit_quantity" min="1" required>
                </div>
                
                <div class="form-group">
                    <label for="edit_description">Offer Description (Optional)</label>
                    <textarea class="form-control-textarea" name="description" id="edit_description" rows="3" placeholder="Add any details about your offer (e.g., condition, delivery terms)"></textarea>
                </div>
                
                <div class="form-group">
                    <button type="submit" name="edit_offer" class="btn-submit">
                        <i class="fas fa-save"></i> Update Offer
                    </button>
                </div>
            </form>
        </div>
    </div>

    <footer>
        <div class="copyright">
            © <?php echo date('Y'); ?> | Created & Designed By <a href="#">Group 8</a>
        </div>
        <div class="sm">
            <a href="#"><i class="fab fa-facebook-f"></i></a>
            <a href="#"><i class="fab fa-instagram"></i></a>
            <a href="#"><i class="fab fa-linkedin-in"></i></a>
            <a href="#"><i class="fab fa-telegram"></i></a>
            <a href="#"><i class="fab fa-github"></i></a>
        </div>
    </footer>

    <script>
        function openOfferModal(itemId, requestId, offerType, title) {
            document.getElementById('modalItemId').value = itemId !== null ? itemId : '';
            document.getElementById('modalRequestId').value = requestId !== null ? requestId : '';
            document.getElementById('modalOfferType').value = offerType;
            document.getElementById('modalTitle').textContent = 'Make Offer for ' + title;
            document.getElementById('offered_price').value = '';
            document.getElementById('quantity').value = '';
            document.getElementById('description').value = '';
            document.getElementById('buyer_name').value = '<?php echo htmlspecialchars($_SESSION['username'] ?? ''); ?>';
            document.getElementById('offerModal').style.display = 'flex';
        }

        function openEditModal(offerId, itemName, buyerName, offeredPrice, quantity, description) {
            document.getElementById('editModalOfferId').value = offerId;
            document.getElementById('editModalTitle').textContent = 'Edit Offer for ' + itemName;
            document.getElementById('edit_buyer_name').value = buyerName;
            document.getElementById('edit_offered_price').value = offeredPrice;
            document.getElementById('edit_quantity').value = quantity;
            document.getElementById('edit_description').value = description;
            document.getElementById('editOfferModal').style.display = 'flex';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        window.onclick = function(event) {
            if (event.target.classList.contains('modal-overlay')) {
                closeModal(event.target.id);
            }
        }

        setTimeout(function() {
            var alerts = document.querySelectorAll('.alert-message');
            alerts.forEach(function(alert) {
                alert.style.display = 'none';
            });
        }, 5000);
    </script>
</body>
</html>
<?php ob_end_flush(); ?>