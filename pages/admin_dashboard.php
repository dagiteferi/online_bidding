<?php
session_start();
require_once '../config/db_connect.php';

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit();
}

// Debug: Print user_id to ensure it's set correctly
error_log("Admin user_id: " . $_SESSION['user_id']);

// Validate that the user_id exists in the users table
try {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    if (!$stmt->fetch()) {
        session_destroy();
        header("Location: login.php?error=invalid_user");
        exit();
    }
} catch (PDOException $e) {
    error_log("Error validating user_id: " . $e->getMessage());
    session_destroy();
    header("Location: login.php?error=database_error");
    exit();
}

$admin_name = "Admin"; // Hardcoded as per login.php

// Handle Post Sell Item
if (isset($_GET['action']) && $_GET['action'] == 'post_sell') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        try {
            $supplier_name = trim($_POST['supplier_name']);
            $item_name = trim($_POST['item_name']);
            $description = trim($_POST['description']);
            $price = floatval($_POST['price']);
            $quantity = intval($_POST['quantity']);
            $user_id = $_SESSION['user_id'];
            $image_path = null;

            // Validate required fields
            if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity <= 0) {
                $error = "All fields are required, and price/quantity must be positive.";
            } else {
                // Handle image upload
                if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                    $max_size = 5 * 1024 * 1024; // 5MB
                    $upload_dir = dirname(__DIR__) . '/uploads/';
                    $file_name = uniqid('item_') . '_' . basename($_FILES['image']['name']);
                    $file_path = $upload_dir . $file_name;
                    $file_type = mime_content_type($_FILES['image']['tmp_name']);

                    if (!is_dir($upload_dir)) {
                        if (!mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                        }
                    }

                    if (!isset($error) && !in_array($file_type, $allowed_types)) {
                        $error = "Only JPEG, PNG, and GIF images are allowed.";
                    } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                        $error = "Image size must be less than 5MB.";
                    } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                        $error = "Failed to upload image.";
                    } else {
                        $image_path = 'uploads/' . $file_name;
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO items (posted_by, supplier_name, item_name, description, price, quantity, status, image, created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, NOW())");
                    $result = $stmt->execute([$user_id, $supplier_name, $item_name, $description, $price, $quantity, $image_path]);
                    if ($result) {
                        $success = "Item posted for sale successfully!";
                        error_log("Item inserted: $item_name, posted_by: $user_id");
                        header("Location: admin_dashboard.php?action=items_for_sell");
                        exit();
                    } else {
                        $error = "Failed to insert item into database.";
                    }
                }
            }
        } catch (PDOException $e) {
            $error = "Error posting item: " . $e->getMessage();
            error_log("Error posting item: " . $e->getMessage());
        }
    }
}

// Handle Edit Item
if (isset($_GET['action']) && $_GET['action'] == 'edit_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        try {
            $supplier_name = trim($_POST['supplier_name']);
            $item_name = trim($_POST['item_name']);
            $description = trim($_POST['description']);
            $price = floatval($_POST['price']);
            $quantity = intval($_POST['quantity']);
            $image_path = $_POST['existing_image'] ?? null;

            // Validate required fields
            if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity < 0) {
                $error = "All fields are required, and price must be positive, quantity must be non-negative.";
            } else {
                // Handle image upload (if a new image is provided)
                if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                    $max_size = 5 * 1024 * 1024; // 5MB
                    $upload_dir = dirname(__DIR__) . '/Uploads/';
                    $file_name = uniqid('item_') . '_' . basename($_FILES['image']['name']);
                    $file_path = $upload_dir . $file_name;
                    $file_type = mime_content_type($_FILES['image']['tmp_name']);

                    if (!is_dir($upload_dir)) {
                        if (!mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                        }
                    }

                    if (!isset($error) && !in_array($file_type, $allowed_types)) {
                        $error = "Only JPEG, PNG, and GIF images are allowed.";
                    } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                        $error = "Image size must be less than 5MB.";
                    } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                        $error = "Failed to upload image.";
                    } else {
                        $image_path = 'Uploads/' . $file_name;
                        // Delete old image if it exists
                        if (!empty($_POST['existing_image'])) {
                            $old_image = dirname(__DIR__) . '/' . $_POST['existing_image'];
                            if (file_exists($old_image)) {
                                unlink($old_image);
                            }
                        }
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("UPDATE items SET supplier_name = ?, item_name = ?, description = ?, price = ?, quantity = ?, image = ? WHERE id = ?");
                    $stmt->execute([$supplier_name, $item_name, $description, $price, $quantity, $image_path, $item_id]);
                    $success = "Item updated successfully!";
                    header("Location: admin_dashboard.php?action=items_for_sell");
                    exit();
                }
            }
        } catch (PDOException $e) {
            $error = "Error updating item: " . $e->getMessage();
        }
    } else {
        // Fetch the item for editing
        try {
            $stmt = $pdo->prepare("SELECT * FROM items WHERE id = ?");
            $stmt->execute([$item_id]);
            $item_to_edit = $stmt->fetch();
            if (!$item_to_edit) {
                $error = "Item not found.";
            }
        } catch (PDOException $e) {
            $error = "Error fetching item: " . $e->getMessage();
        }
    }
}

// Handle Close Item
if (isset($_GET['action']) && $_GET['action'] == 'close_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE id = ?");
        $stmt->execute([$item_id]);
        $success = "Item marked as closed successfully!";
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error closing item: " . $e->getMessage();
    }
}

// Handle Reopen Item
if (isset($_GET['action']) && $_GET['action'] == 'reopen_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        $stmt = $pdo->prepare("UPDATE items SET status = 'open' WHERE id = ?");
        $stmt->execute([$item_id]);
        $success = "Item reopened successfully!";
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error reopening item: " . $e->getMessage();
    }
}

// Handle Delete Item
if (isset($_GET['action']) && $_GET['action'] == 'delete_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        // Fetch the item to get the image path
        $stmt = $pdo->prepare("SELECT image FROM items WHERE id = ?");
        $stmt->execute([$item_id]);
        $item = $stmt->fetch();
        if ($item) {
            // Delete the image file if it exists
            if (!empty($item['image'])) {
                $image_path = dirname(__DIR__) . '/' . $item['image'];
                if (file_exists($image_path)) {
                    unlink($image_path);
                }
            }
            // Delete the item from the database
            $stmt = $pdo->prepare("DELETE FROM items WHERE id = ?");
            $stmt->execute([$item_id]);
            $success = "Item permanently deleted successfully!";
        } else {
            $error = "Item not found.";
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error deleting item: " . $e->getMessage();
    }
}

// Handle Post Buy Item
if (isset($_GET['action']) && $_GET['action'] == 'post_buy') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        try {
            $item_name = trim($_POST['item_name']);
            $description = trim($_POST['description']);
            $max_price = floatval($_POST['max_price']);
            $quantity = intval($_POST['quantity']);
            $user_id = $_SESSION['user_id'];
            $image_path = null;

            if (empty($item_name) || empty($description) || $max_price <= 0 || $quantity <= 0) {
                $error = "All fields are required, and max price/quantity must be positive.";
            } else {
                if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                    $max_size = 5 * 1024 * 1024; // 5MB
                    $upload_dir = dirname(__DIR__) . '/Uploads/';
                    $file_name = uniqid('buy_request_') . '_' . basename($_FILES['image']['name']);
                    $file_path = $upload_dir . $file_name;
                    $file_type = mime_content_type($_FILES['image']['tmp_name']);

                    if (!is_dir($upload_dir)) {
                        if (!mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                        }
                    }

                    if (!isset($error) && !in_array($file_type, $allowed_types)) {
                        $error = "Only JPEG, PNG, and GIF images are allowed.";
                    } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                        $error = "Image size must be less than 5MB.";
                    } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                        $error = "Failed to upload image.";
                    } else {
                        $image_path = 'Uploads/' . $file_name;
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO buy_requests (user_id, item_name, description, max_price, quantity, status, image, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?, NOW())");
                    $stmt->execute([$user_id, $item_name, $description, $max_price, $quantity, $image_path]);
                    $success = "Buy request posted successfully!";
                    header("Location: admin_dashboard.php?action=buy_requests");
                    exit();
                }
            }
        } catch (PDOException $e) {
            $error = "Error posting buy request: " . $e->getMessage();
        }
    }
}

// Handle Cancel Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'cancel_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE id = ? AND user_id = ?");
        $stmt->execute([$request_id, $_SESSION['user_id']]);
        $success = "Buy request canceled successfully!";
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error canceling buy request: " . $e->getMessage();
    }
}

// Handle View Offers for Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'view_offers' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("SELECT o.*, u.username, br.item_name 
            FROM offers o 
            JOIN users u ON o.user_id = u.id 
            JOIN buy_requests br ON o.request_id = br.id 
            WHERE o.request_id = ? AND o.status = 'pending'");
        $stmt->execute([$request_id]);
        $buy_request_offers = $stmt->fetchAll();
    } catch (PDOException $e) {
        $error = "Error fetching offers: " . $e->getMessage();
    }
}

// Handle Close Offer
if (isset($_GET['action']) && $_GET['action'] == 'close_offer' && isset($_GET['offer_id'])) {
    $offer_id = intval($_GET['offer_id']);
    try {
        $stmt = $pdo->prepare("UPDATE offers SET status = 'closed' WHERE id = ?");
        $stmt->execute([$offer_id]);
        $success = "Offer closed successfully!";
        header("Location: admin_dashboard.php?action=offers");
        exit();
    } catch (PDOException $e) {
        $error = "Error closing offer: " . $e->getMessage();
    }
}

// Handle Delete Offer
if (isset($_GET['action']) && $_GET['action'] == 'delete_offer' && isset($_GET['offer_id'])) {
    $offer_id = intval($_GET['offer_id']);
    try {
        $stmt = $pdo->prepare("DELETE FROM offers WHERE id = ?");
        $stmt->execute([$offer_id]);
        $success = "Offer deleted successfully!";
        header("Location: admin_dashboard.php?action=offers");
        exit();
    } catch (PDOException $e) {
        $error = "Error deleting offer: " . $e->getMessage();
    }
}

// Handle Offer Actions
if (isset($_GET['action']) && $_GET['action'] == 'offer_action' && isset($_GET['offer_id']) && isset($_GET['type'])) {
    $offer_id = intval($_GET['offer_id']);
    $action_type = $_GET['type'];

    try {
        $stmt = $pdo->prepare("SELECT o.offered_price, o.quantity, o.item_id, o.request_id, o.user_id AS buyer_id, i.posted_by AS seller_id, i.quantity AS available_quantity 
            FROM offers o 
            LEFT JOIN items i ON o.item_id = i.id 
            WHERE o.id = ?");
        $stmt->execute([$offer_id]);
        $offer = $stmt->fetch();

        if (!$offer) {
            $error = "Offer not found.";
        } else {
            if ($action_type == 'accept') {
                $stmt = $pdo->prepare("UPDATE offers SET status = 'accepted' WHERE id = ?");
                $stmt->execute([$offer_id]);

                if ($offer['item_id']) {
                    // Buy offer (on item for sale)
                    $stmt = $pdo->prepare("INSERT INTO transactions (item_id, offer_id, buyer_or_seller_id, final_price, quantity, created_at) 
                        VALUES (?, ?, ?, ?, ?, NOW())");
                    $stmt->execute([
                        $offer['item_id'],
                        $offer_id,
                        $offer['buyer_id'],
                        $offer['offered_price'],
                        $offer['quantity']
                    ]);

                    // Update item quantity
                    $new_quantity = $offer['available_quantity'] - $offer['quantity'];
                    $stmt = $pdo->prepare("UPDATE items SET quantity = ? WHERE id = ?");
                    $stmt->execute([$new_quantity, $offer['item_id']]);

                    if ($new_quantity <= 0) {
                        $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE id = ?");
                        $stmt->execute([$offer['item_id']]);
                    }
                } elseif ($offer['request_id']) {
                    // Sell offer (on buy request)
                    $stmt = $pdo->prepare("SELECT quantity FROM buy_requests WHERE id = ?");
                    $stmt->execute([$offer['request_id']]);
                    $request = $stmt->fetch();
                    $requested_quantity = $request['quantity'];

                    $stmt = $pdo->prepare("INSERT INTO transactions (request_id, offer_id, buyer_or_seller_id, final_price, quantity, created_at) 
                        VALUES (?, ?, ?, ?, ?, NOW())");
                    $stmt->execute([
                        $offer['request_id'],
                        $offer_id,
                        $offer['buyer_id'],
                        $offer['offered_price'],
                        $offer['quantity']
                    ]);

                    $new_quantity = $requested_quantity - $offer['quantity'];
                    $stmt = $pdo->prepare("UPDATE buy_requests SET quantity = ? WHERE id = ?");
                    $stmt->execute([$new_quantity, $offer['request_id']]);

                    if ($new_quantity <= 0) {
                        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE id = ?");
                        $stmt->execute([$offer['request_id']]);
                    }
                }

                $success = "Offer accepted successfully!";
            } elseif ($action_type == 'reject') {
                $stmt = $pdo->prepare("UPDATE offers SET status = 'rejected' WHERE id = ?");
                $stmt->execute([$offer_id]);
                $success = "Offer rejected successfully!";
            } else {
                $error = "Invalid action type.";
            }
        }
    } catch (PDOException $e) {
        $error = "Error processing offer: " . $e->getMessage();
    }

    header("Location: admin_dashboard.php?action=offers");
    exit();
}

// Fetch counts for dashboard
$items_for_sell = $buy_requests = $pending_offers = 0;
try {
    // Count all items for admin (not just posted_by)
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM items");
    $stmt->execute();
    $items_for_sell = $stmt->fetchColumn();
    error_log("Items for sell count (admin): $items_for_sell");

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM buy_requests WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $buy_requests = $stmt->fetchColumn();

    // Count pending offers (both buy and sell offers) submitted by users
    $pending_buy_offers = 0;
    $pending_sell_offers = 0;

    // Buy offers: Offers on items posted by the admin
    $stmt = $pdo->prepare("SELECT COUNT(*) 
        FROM offers o 
        JOIN items i ON o.item_id = i.id 
        WHERE i.posted_by = ? AND o.status = 'pending'");
    $stmt->execute([$_SESSION['user_id']]);
    $pending_buy_offers = $stmt->fetchColumn();
    error_log("Pending buy offers (on admin's items): $pending_buy_offers");

    // Sell offers: Offers on buy requests posted by the admin
    $stmt = $pdo->prepare("SELECT COUNT(*) 
        FROM offers o 
        JOIN buy_requests br ON o.request_id = br.id 
        WHERE br.user_id = ? AND o.status = 'pending'");
    $stmt->execute([$_SESSION['user_id']]);
    $pending_sell_offers = $stmt->fetchColumn();
    error_log("Pending sell offers (on admin's buy requests): $pending_sell_offers");

    $pending_offers = $pending_buy_offers + $pending_sell_offers;
    error_log("Total pending offers: $pending_offers");

    // Debug: Fetch actual offer records to inspect
    $stmt = $pdo->prepare("SELECT o.*, i.posted_by AS item_posted_by, br.user_id AS request_user_id 
        FROM offers o 
        LEFT JOIN items i ON o.item_id = i.id 
        LEFT JOIN buy_requests br ON o.request_id = br.id 
        WHERE (i.posted_by = ? OR br.user_id = ?) AND o.status = 'pending'");
    $stmt->execute([$_SESSION['user_id'], $_SESSION['user_id']]);
    $debug_offers = $stmt->fetchAll();
    error_log("Debug offers: " . print_r($debug_offers, true));
} catch (PDOException $e) {
    $error = "Error fetching dashboard stats: " . $e->getMessage();
    error_log("Error fetching dashboard stats: " . $e->getMessage());
}

// Fetch items below min stock (assume min stock = 5 for demo)
$min_stock = 5;
$low_stock_items = [];
try {
    $stmt = $pdo->prepare("SELECT item_name FROM items WHERE quantity < ? AND status = 'open'");
    $stmt->execute([$min_stock]);
    $low_stock_items = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $error = "Error fetching low stock items: " . $e->getMessage();
}

// Fetch items for sale (all items for admin)
$items = [];
try {
    $stmt = $pdo->prepare("SELECT i.*, u.username AS posted_by_name 
        FROM items i 
        JOIN users u ON i.posted_by = u.id");
    $stmt->execute();
    $items = $stmt->fetchAll();
    error_log("Fetched items: " . count($items));
} catch (PDOException $e) {
    $error = "Error fetching items: " . $e->getMessage();
}

// Fetch buy requests
$requests = [];
try {
    $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $requests = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching buy requests: " . $e->getMessage();
}

// Fetch pending offers (both buy and sell)
$buy_offers = $sell_offers = [];
try {
    // Sorting parameters
    $buy_sort_field = $_GET['buy_sort_field'] ?? 'offered_price';
    $buy_sort_order = $_GET['buy_sort_order'] ?? 'ASC';
    $sell_sort_field = $_GET['sell_sort_field'] ?? 'offered_price';
    $sell_sort_order = $_GET['sell_sort_order'] ?? 'ASC';

    // Validate sort fields and order
    $valid_fields = ['offered_price', 'created_at'];
    $valid_orders = ['ASC', 'DESC'];
    $buy_sort_field = in_array($buy_sort_field, $valid_fields) ? $buy_sort_field : 'offered_price';
    $buy_sort_order = in_array($buy_sort_order, $valid_orders) ? $buy_sort_order : 'ASC';
    $sell_sort_field = in_array($sell_sort_field, $valid_fields) ? $sell_sort_field : 'offered_price';
    $sell_sort_order = in_array($sell_sort_order, $valid_orders) ? $sell_sort_order : 'ASC';

    // Fetch buy offers (offers on items for sale)
    $stmt = $pdo->prepare("SELECT o.*, i.item_name, u.username 
        FROM offers o 
        JOIN items i ON o.item_id = i.id 
        JOIN users u ON o.user_id = u.id 
        WHERE i.posted_by = ? AND o.status = 'pending' 
        ORDER BY o.$buy_sort_field $buy_sort_order");
    $stmt->execute([$_SESSION['user_id']]);
    $buy_offers = $stmt->fetchAll();

    // Fetch sell offers (offers on buy requests)
    $stmt = $pdo->prepare("SELECT o.*, br.item_name, u.username 
        FROM offers o 
        JOIN buy_requests br ON o.request_id = br.id 
        JOIN users u ON o.user_id = u.id 
        WHERE br.user_id = ? AND o.status = 'pending' 
        ORDER BY o.$sell_sort_field $sell_sort_order");
    $stmt->execute([$_SESSION['user_id']]);
    $sell_offers = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching offers: " . $e->getMessage();
}

// Fetch transactions
$transactions = [];
try {
    $stmt = $pdo->prepare("SELECT t.*, 
        i.item_name AS item_name_sell, 
        br.item_name AS item_name_buy, 
        ub.username AS buyer, 
        us.username AS seller 
    FROM transactions t 
    LEFT JOIN items i ON t.item_id = i.id 
    LEFT JOIN buy_requests br ON t.request_id = br.id 
    JOIN users ub ON t.buyer_or_seller_id = ub.id 
    LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id) 
    WHERE (i.posted_by = ? OR br.user_id = ?)");
    $stmt->execute([$_SESSION['user_id'], $_SESSION['user_id']]);
    $transactions = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching transactions: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="../css/admin.css">
    <link rel="stylesheet" href="../css/style.css">
    <script src="../javaScript/scripts.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <style>
        .item-image, .request-image {
            max-width: 100%;
            max-height: 150px;
            margin-bottom: 10px;
            border-radius: 5px;
            object-fit: cover;
        }
        .item-details {
            margin-top: 10px;
            padding: 10px;
            border-top: 1px solid #ddd;
        }
        .item-actions a, .offer-actions a {
            margin-right: 5px;
        }
        .closed-item {
            background-color: #f8d7da;
            opacity: 0.8;
            position: relative;
        }
        .closed-item::after {
            content: 'CLOSED';
            position: absolute;
            top: 10px;
            right: 10px;
            background-color: #e74c3c;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 12px;
        }
        .admin-btn.reopen {
            background-color: #2ecc71;
        }
        .admin-btn.reopen:hover {
            background-color: #27ae60;
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
            background-color: #48dbfb;
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
        .sort-form {
            margin-bottom: 20px;
        }
        .sort-form select {
            padding: 8px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .sort-form button {
            padding: 8px 15px;
            background-color: #48dbfb;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .sort-form button:hover {
            background-color: #3aa8d8;
        }
    </style>
</head>

<body>
    <!-- Navbar -->
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
                <a href="admin_dashboard.php" class="active">Dashboard</a>
                <a href="../logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <!-- Admin Header -->
    <div class="admin-header">
        <div class="inner-width">
            <h1>Welcome, <?php echo htmlspecialchars($admin_name); ?></h1>
            <p>Manage your inventory, sales, and purchases efficiently</p>
        </div>
    </div>

    <div class="admin-dashboard">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-user-shield"></i>
                <span>Admin Panel</span>
            </div>
            <ul>
                <li><a href="?action=dashboard"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="?action=post_sell"><i class="fas fa-tag"></i> Post Sell Item</a></li>
                <li><a href="?action=post_buy"><i class="fas fa-shopping-cart"></i> Post Buy Item</a></li>
                <li><a href="?action=items_for_sell"><i class="fas fa-box-open"></i> Items for Sale</a></li>
                <li><a href="?action=buy_requests"><i class="fas fa-hand-holding-usd"></i> Active Buy Requests</a></li>
                <li><a href="?action=offers"><i class="fas fa-exchange-alt"></i> Offers</a></li>
                <li><a href="?action=transactions"><i class="fas fa-receipt"></i> Transactions</a></li>
                <li><a href="?action=report"><i class="fas fa-chart-pie"></i> Reports</a></li>
                <li><a href="../logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <?php if (isset($error)): ?>
                <div class="alert-card error">
                    <p><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (isset($success)): ?>
                <div class="alert-card success">
                    <p><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></p>
                </div>
            <?php endif; ?>

            <?php if (!isset($_GET['action']) || $_GET['action'] == 'dashboard'): ?>
                <!-- Dashboard Overview -->
                <div class="dashboard-stats">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="stat-card">
                                <i class="fas fa-tag"></i>
                                <div class="stat-number"><?php echo htmlspecialchars($items_for_sell); ?></div>
                                <h3>Items for Sale</h3>
                                <p>Total items in inventory</p>
                                <a href="?action=items_for_sell" class="admin-btn">View Items</a>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="stat-card">
                                <i class="fas fa-shopping-cart"></i>
                                <div class="stat-number"><?php echo htmlspecialchars($buy_requests); ?></div>
                                <h3>Active Buy Requests</h3>
                                <p>Total purchase requests</p>
                                <a href="?action=buy_requests" class="admin-btn">View Requests</a>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="stat-card">
                                <i class="fas fa-exchange-alt"></i>
                                <div class="stat-number"><?php echo htmlspecialchars($pending_offers); ?></div>
                                <h3>Pending Offers</h3>
                                <p>Offers awaiting your response</p>
                                <a href="?action=offers" class="admin-btn">View Offers</a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Alerts Section -->
                <div class="alert-card warning">
                    <h3><i class="fas fa-exclamation-triangle"></i> Low Stock Alerts</h3>
                    <?php if (!empty($low_stock_items)): ?>
                        <ul>
                            <?php foreach ($low_stock_items as $item): ?>
                                <li><?php echo htmlspecialchars($item); ?> - Needs restocking</li>
                            <?php endforeach; ?>
                        </ul>
                    <?php else: ?>
                        <p>All items are sufficiently stocked.</p>
                    <?php endif; ?>
                </div>
                
                <!-- Quick Actions -->
                <div class="row quick-actions">
                    <div class="col-md-6">
                        <a href="?action=post_sell" class="admin-btn">
                            <i class="fas fa-plus"></i> Add New Item
                        </a>
                    </div>
                    <div class="col-md-6">
                        <a href="?action=post_buy" class="admin-btn">
                            <i class="fas fa-hand-holding-usd"></i> Create Buy Request
                        </a>
                    </div>
                </div>

            <?php elseif ($_GET['action'] == 'post_sell'): ?>
                <!-- Post Sell Item Form -->
                <div class="form-card">
                    <h2><i class="fas fa-tag"></i> Post Item for Sale</h2>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="form-group">
                            <input type="text" name="supplier_name" class="input" placeholder="Supplier Name" required />
                        </div>
                        <div class="form-group">
                            <input type="text" name="item_name" class="input" placeholder="Item Name" required />
                        </div>
                        <div class="form-group">
                            <textarea name="description" class="input" placeholder="Item Description" rows="4" required></textarea>
                        </div>
                        <div class="form-group">
                            <input type="number" name="price" class="input" placeholder="Price of Item ($)" step="0.01" required />
                        </div>
                        <div class="form-group">
                            <input type="number" name="quantity" class="input" placeholder="Quantity" required />
                        </div>
                        <div class="form-group">
                            <label for="item_image">Upload Image (optional):</label>
                            <input type="file" name="image" id="item_image" class="input" accept="image/*" />
                        </div>
                        <button type="submit" class="admin-btn full-width">
                            <i class="fas fa-save"></i> Submit Item
                        </button>
                    </form>
                </div>

            <?php elseif ($_GET['action'] == 'edit_item' && isset($item_to_edit)): ?>
                <!-- Edit Item Form -->
                <div class="form-card">
                    <h2><i class="fas fa-edit"></i> Edit Item</h2>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? ''); ?>">
                        <div class="form-group">
                            <label>Supplier Name:</label>
                            <input type="text" name="supplier_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['supplier_name']); ?>" required />
                        </div>
                        <div class="form-group">
                            <label>Item Name:</label>
                            <input type="text" name="item_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['item_name']); ?>" required />
                        </div>
                        <div class="form-group">
                            <label>Description:</label>
                            <textarea name="description" class="input" rows="4" required><?php echo htmlspecialchars($item_to_edit['description']); ?></textarea>
                        </div>
                        <div class="form-group">
                            <label>Price ($):</label>
                            <input type="number" name="price" class="input" value="<?php echo htmlspecialchars($item_to_edit['price']); ?>" step="0.01" required />
                        </div>
                        <div class="form-group">
                            <label>Quantity:</label>
                            <input type="number" name="quantity" class="input" value="<?php echo htmlspecialchars($item_to_edit['quantity']); ?>" required />
                        </div>
                        <div class="form-group">
                            <label>Current Image:</label>
                            <?php if (!empty($item_to_edit['image'])): ?>
                                <img src="../<?php echo htmlspecialchars($item_to_edit['image']); ?>" alt="Current Image" class="item-image">
                            <?php else: ?>
                                <p>No image uploaded.</p>
                            <?php endif; ?>
                            <label for="item_image">Upload New Image (optional):</label>
                            <input type="file" name="image" id="item_image" class="input" accept="image/*" />
                        </div>
                        <button type="submit" class="admin-btn full-width">
                            <i class="fas fa-save"></i> Update Item
                        </button>
                        <a href="?action=items_for_sell" class="admin-btn danger full-width">
                            <i class="fas fa-arrow-left"></i> Cancel
                        </a>
                    </form>
                </div>

            <?php elseif ($_GET['action'] == 'post_buy'): ?>
                <!-- Post Buy Item Form -->
                <div class="form-card">
                    <h2><i class="fas fa-hand-holding-usd"></i> Post Buy Request</h2>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="form-group">
                            <input type="text" name="item_name" class="input" placeholder="Item Name" required />
                        </div>
                        <div class="form-group">
                            <textarea name="description" class="input" placeholder="Item Description" rows="4" required></textarea>
                        </div>
                        <div class="form-group">
                            <input type="number" name="max_price" class="input" placeholder="Max Price Willing to Pay ($)" step="0.01" required />
                        </div>
                        <div class="form-group">
                            <input type="number" name="quantity" class="input" placeholder="Quantity" required />
                        </div>
                        <div class="form-group">
                            <label for="buy_image">Upload Image (optional):</label>
                            <input type="file" name="image" id="buy_image" class="input" accept="image/*" />
                        </div>
                        <button type="submit" class="admin-btn full-width">
                            <i class="fas fa-paper-plane"></i> Submit Request
                        </button>
                    </form>
                </div>

            <?php elseif ($_GET['action'] == 'items_for_sell'): ?>
                <!-- Items for Sell -->
                <h2><i class="fas fa-box-open"></i> Items for Sale (<?php echo count($items); ?>)</h2>
                <?php if ($items): ?>
                    <div class="row">
                        <?php foreach ($items as $item): ?>
                            <div class="col-md-6">
                                <div class="item-card <?php echo ($item['status'] === 'closed') ? 'closed-item' : ''; ?>">
                                    <?php if (!empty($item['image'])): ?>
                                        <img src="../<?php echo htmlspecialchars($item['image']); ?>" alt="<?php echo htmlspecialchars($item['item_name']); ?>" class="item-image">
                                    <?php endif; ?>
                                    <h3><?php echo htmlspecialchars($item['item_name']); ?></h3>
                                    <p><strong>Supplier:</strong> <?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A'); ?></p>
                                    <p><?php echo htmlspecialchars($item['description']); ?></p>
                                    <p class="price">Price: $<?php echo number_format($item['price'], 2); ?></p>
                                    <p class="quantity">Quantity: <?php echo htmlspecialchars($item['quantity']); ?></p>
                                    <div class="item-details">
                                        <p><strong>Posted By:</strong> <?php echo htmlspecialchars($item['posted_by_name']); ?></p>
                                        <p><strong>Created At:</strong> <?php echo htmlspecialchars($item['created_at'] ?? 'N/A'); ?></p>
                                        <p><strong>Status:</strong> <?php echo htmlspecialchars($item['status'] ?? 'N/A'); ?></p>
                                    </div>
                                    <div class="item-actions">
                                        <a href="?action=edit_item&item_id=<?php echo $item['id']; ?>" class="admin-btn">
                                            <i class="fas fa-edit"></i> Edit
                                        </a>
                                        <?php if ($item['status'] !== 'closed'): ?>
                                            <a href="?action=close_item&item_id=<?php echo $item['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to mark this item as closed? It will no longer be available for offers, but will remain in your inventory.');">
                                                <i class="fas fa-times"></i> Mark as Closed
                                            </a>
                                        <?php else: ?>
                                            <a href="?action=reopen_item&item_id=<?php echo $item['id']; ?>" class="admin-btn reopen" onclick="return confirm('Are you sure you want to reopen this item? It will become available for offers again.');">
                                                <i class="fas fa-undo"></i> Reopen
                                            </a>
                                        <?php endif; ?>
                                        <a href="?action=delete_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to permanently delete this item? This action cannot be undone and will remove the item from both admin and user dashboards.');">
                                            <i class="fas fa-trash"></i> Delete
                                        </a>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-box-open"></i>
                        <p>No items currently for sale.</p>
                        <a href="?action=post_sell" class="admin-btn">
                            <i class="fas fa-plus"></i> Add New Item
                        </a>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'buy_requests'): ?>
                <!-- Buy Requests -->
                <h2><i class="fas fa-hand-holding-usd"></i> Active Buy Requests (<?php echo count($requests); ?>)</h2>
                <?php if ($requests): ?>
                    <div class="row">
                        <?php foreach ($requests as $request): ?>
                            <div class="col-md-6">
                                <div class="item-card <?php echo ($request['status'] === 'closed') ? 'closed-item' : ''; ?>">
                                    <?php if (!empty($request['image'])): ?>
                                        <img src="../<?php echo htmlspecialchars($request['image']); ?>" alt="<?php echo htmlspecialchars($request['item_name']); ?>" class="request-image">
                                    <?php endif; ?>
                                    <h3><?php echo htmlspecialchars($request['item_name']); ?></h3>
                                    <p><?php echo htmlspecialchars($request['description']); ?></p>
                                    <p class="price">Max Price: $<?php echo number_format($request['max_price'], 2); ?></p>
                                    <p class="quantity">Quantity: <?php echo htmlspecialchars($request['quantity']); ?></p>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($request['status']); ?></p>
                                    <div class="item-actions">
                                        <?php if ($request['status'] !== 'closed'): ?>
                                            <a href="?action=view_offers&request_id=<?php echo $request['id']; ?>" class="admin-btn">
                                                <i class="fas fa-search"></i> View Offers
                                            </a>
                                            <a href="?action=cancel_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to cancel this buy request?');">
                                                <i class="fas fa-times"></i> Cancel
                                            </a>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-shopping-cart"></i>
                        <p>No active buy requests.</p>
                        <a href="?action=post_buy" class="admin-btn">
                            <i class="fas fa-plus"></i> Create Buy Request
                        </a>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'view_offBasic Infoers' && isset($buy_request_offers)): ?>
                <!-- View Offers for Buy Request -->
                <h2><i class="fas fa-exchange-alt"></i> Offers for Buy Request</h2>
                <?php if ($buy_request_offers): ?>
                    <div class="offers-table-container">
                        <table class="offers-table">
                            <thead>
                                <tr>
                                    <th>From</th>
                                    <th>Buyer Name</th>
                                    <th>Offered Price ($)</th>
                                    <th>Quantity</th>
                                    <th>Description</th>
                                    <th>Offer Time</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($buy_request_offers as $offer): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($offer['username']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['buyer_name']); ?></td>
                                        <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                        <td><?php echo htmlspecialchars($offer['quantity']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['description'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($offer['created_at']); ?></td>
                                        <td class="offer-actions">
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success">
                                                <i class="fas fa-check"></i> Accept
                                            </a>
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger">
                                                <i class="fas fa-times"></i> Reject
                                            </a>
                                            <a href="?action=close_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');">
                                                <i class="fas fa-times-circle"></i> Close
                                            </a>
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? This action cannot be undone.');">
                                                <i class="fas fa-trash"></i> Delete
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-exchange-alt"></i>
                        <p>No offers for this buy request.</p>
                        <a href="?action=buy_requests" class="admin-btn">
                            <i class="fas fa-arrow-left"></i> Back to Active Buy Requests
                        </a>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'offers'): ?>
                <!-- Pending Offers -->
                <h2><i class="fas fa-exchange-alt"></i> Pending Offers</h2>

                <!-- Buy Offers (Offers on Items for Sale) -->
                <h3>Buy Offers (Offers on Your Items for Sale) (<?php echo count($buy_offers); ?>)</h3>
                <div class="sort-form">
                    <form method="GET" action="admin_dashboard.php">
                        <input type="hidden" name="action" value="offers">
                        <label for="buy_sort_field">Sort By:</label>
                        <select name="buy_sort_field" id="buy_sort_field">
                            <option value="offered_price" <?php echo ($buy_sort_field == 'offered_price') ? 'selected' : ''; ?>>Offered Price</option>
                            <option value="created_at" <?php echo ($buy_sort_field == 'created_at') ? 'selected' : ''; ?>>Offer Time</option>
                        </select>
                        <label for="buy_sort_order">Order:</label>
                        <select name="buy_sort_order" id="buy_sort_order">
                            <option value="ASC" <?php echo ($buy_sort_order == 'ASC') ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo ($buy_sort_order == 'DESC') ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit">Sort</button>
                    </form>
                </div>
                <?php if ($buy_offers): ?>
                    <div class="offers-table-container">
                        <table class="offers-table">
                            <thead>
                                <tr>
                                    <th>Item Name</th>
                                    <th>From</th>
                                    <th>Buyer Name</th>
                                    <th>Offered Price ($)</th>
                                    <th>Quantity</th>
                                    <th>Description</th>
                                    <th>Offer Time</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($buy_offers as $offer): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($offer['item_name']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['username']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['buyer_name']); ?></td>
                                        <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                        <td><?php echo htmlspecialchars($offer['quantity']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['description'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($offer['created_at']); ?></td>
                                        <td class="offer-actions">
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success">
                                                <i class="fas fa-check"></i> Accept
                                            </a>
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger">
                                                <i class="fas fa-times"></i> Reject
                                            </a>
                                            <a href="?action=close_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');">
                                                <i class="fas fa-times-circle"></i> Close
                                            </a>
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? This action cannot be undone.');">
                                                <i class="fas fa-trash"></i> Delete
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-exchange-alt"></i>
                        <p>No pending buy offers at the moment.</p>
                    </div>
                <?php endif; ?>

                <!-- Sell Offers (Offers on Buy Requests) -->
                <h3>Sell Offers (Offers on Your Buy Requests) (<?php echo count($sell_offers); ?>)</h3>
                <div class="sort-form">
                    <form method="GET" action="admin_dashboard.php">
                        <input type="hidden" name="action" value="offers">
                        <label for="sell_sort_field">Sort By:</label>
                        <select name="sell_sort_field" id="sell_sort_field">
                            <option value="offered_price" <?php echo ($sell_sort_field == 'offered_price') ? 'selected' : ''; ?>>Offered Price</option>
                            <option value="created_at" <?php echo ($sell_sort_field == 'created_at') ? 'selected' : ''; ?>>Offer Time</option>
                        </select>
                        <label for="sell_sort_order">Order:</label>
                        <select name="sell_sort_order" id="sell_sort_order">
                            <option value="ASC" <?php echo ($sell_sort_order == 'ASC') ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo ($sell_sort_order == 'DESC') ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit">Sort</button>
                    </form>
                </div>
                <?php if ($sell_offers): ?>
                    <div class="offers-table-container">
                        <table class="offers-table">
                            <thead>
                                <tr>
                                    <th>Requested Item</th>
                                    <th>From</th>
                                    <th>Buyer Name</th>
                                    <th>Offered Price ($)</th>
                                    <th>Quantity</th>
                                    <th>Description</th>
                                    <th>Offer Time</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($sell_offers as $offer): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($offer['item_name']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['username']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['buyer_name']); ?></td>
                                        <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                        <td><?php echo htmlspecialchars($offer['quantity']); ?></td>
                                        <td><?php echo htmlspecialchars($offer['description'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($offer['created_at']); ?></td>
                                        <td class="offer-actions">
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success">
                                                <i class="fas fa-check"></i> Accept
                                            </a>
                                            <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger">
                                                <i class="fas fa-times"></i> Reject
                                            </a>
                                            <a href="?action=close_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');">
                                                <i class="fas fa-times-circle"></i> Close
                                            </a>
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? This action cannot be undone.');">
                                                <i class="fas fa-trash"></i> Delete
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-exchange-alt"></i>
                        <p>No pending sell offers at the moment.</p>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'transactions'): ?>
                <!-- Transactions -->
                <h2><i class="fas fa-receipt"></i> Transactions</h2>
                <?php if ($transactions): ?>
                    <div class="row">
                        <?php foreach ($transactions as $transaction): ?>
                            <div class="col-md-6">
                                <div class="item-card">
                                    <h3>Transaction for <?php echo htmlspecialchars($transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A'); ?></h3>
                                    <p><strong>Buyer:</strong> <?php echo htmlspecialchars($transaction['buyer']); ?></p>
                                    <p><strong>Seller:</strong> <?php echo htmlspecialchars($transaction['seller']); ?></p>
                                    <p class="price">Final Price: $<?php echo number_format($transaction['final_price'], 2); ?></p>
                                    <p><strong>Quantity:</strong> <?php echo htmlspecialchars($transaction['quantity']); ?></p>
                                    <p><strong>Transaction Date:</strong> <?php echo htmlspecialchars($transaction['created_at']); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-receipt"></i>
                        <p>No transactions available.</p>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'report'): ?>
                <!-- Reports -->
                <h2><i class="fas fa-chart-pie"></i> Reports</h2>
                <div class="report-card">
                    <h3>Sales Summary</h3>
                    <p>Total Items Sold: <?php echo count($transactions); ?></p>
                    <p>Total Revenue: $<?php
                        $total_revenue = 0;
                        foreach ($transactions as $t) {
                            $total_revenue += $t['final_price'] * $t['quantity'];
                        }
                        echo number_format($total_revenue, 2);
                    ?></p>
                </div>
                <div class="report-card">
                    <h3>Inventory Overview</h3>
                    <p>Total Items for Sale: <?php echo htmlspecialchars($items_for_sell); ?></p>
                    <p>Low Stock Items: <?php echo count($low_stock_items); ?></p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Footer -->
    <footer>
        <div class="copyright">
            © 2025 | Created & Designed By <a href="#home">Group 8</a>
        </div>
        <div class="sm">
            <a href="#/"><i class="fa fa-facebook" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-instagram" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-twitter" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
        </div>
    </footer>
</body>
</html>