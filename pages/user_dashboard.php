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
    <!-- <link rel="stylesheet" href="../css/admin.css"> -->
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="../css/user_dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <script src="../javaScript/scripts.js"></script>
    <style>
     


    </style>
</head>
<body>
    
<nav class="navbar">
        <div class="inner-width">
            <a href="index.php" class="logo"></a>
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
    
    <section id="home">
        <div class="inner-width">
        <div class="dashboard-container">
        <div class="welcome-banner">
            <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?>!</h1>
            <p>Manage your offers, browse available items, and respond to admin buy requests</p>
            <a href="#your-offers" class="btn-view-offers"><i class="fas fa-handshake"></i> View Your Offers</a>
        </div>
        </div>
    </section>
    
        
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