<?php
session_start();
require_once '../config/db_connect.php';

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit();
}

// Validate that the user_id exists in the users table
try {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? AND is_admin = 1");
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

// Check and update items and buy requests with expired close_time
try {
    $current_time = date('Y-m-d H:i:s');
    // Update items
    $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE close_time IS NOT NULL AND close_time <= ? AND status = 'open'");
    $stmt->execute([$current_time]);
    // Update buy requests
    $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE close_time IS NOT NULL AND close_time <= ? AND status = 'open'");
    $stmt->execute([$current_time]);
} catch (PDOException $e) {
    error_log("Error updating expired close times: " . $e->getMessage());
}

// Handle Post Sell Item
if (isset($_GET['action']) && $_GET['action'] == 'post_sell') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        try {
            $supplier_name = trim($_POST['supplier_name']);
            $item_name = trim($_POST['item_name']);
            $description = trim($_POST['description']);
            $price = floatval($_POST['price']);
            $quantity = intval($_POST['quantity']);
            $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
            $user_id = $_SESSION['user_id'];
            $image_path = null;

            // Validate required fields
            if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity <= 0) {
                $error = "All fields are required, and price/quantity must be positive.";
            } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                $error = "Close time must be in the future.";
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
                    $stmt = $pdo->prepare("INSERT INTO items (posted_by, supplier_name, item_name, description, price, quantity, status, image, close_time, created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, NOW())");
                    $result = $stmt->execute([$user_id, $supplier_name, $item_name, $description, $price, $quantity, $image_path, $close_time]);
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
            $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
            $image_path = $_POST['existing_image'] ?? null;

            // Validate required fields
            if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity < 0) {
                $error = "All fields are required, and price must be positive, quantity must be non-negative.";
            } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                $error = "Close time must be in the future.";
            } else {
                // Handle image upload (if a new image is provided)
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
                    $stmt = $pdo->prepare("UPDATE items SET supplier_name = ?, item_name = ?, description = ?, price = ?, quantity = ?, image = ?, close_time = ? WHERE id = ? AND posted_by = ?");
                    $stmt->execute([$supplier_name, $item_name, $description, $price, $quantity, $image_path, $close_time, $item_id, $_SESSION['user_id']]);
                    if ($stmt->rowCount() > 0) {
                        $success = "Item updated successfully!";
                    } else {
                        $error = "Item not found or you don't have permission to edit it.";
                    }
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
            $stmt = $pdo->prepare("SELECT * FROM items WHERE id = ? AND posted_by = ?");
            $stmt->execute([$item_id, $_SESSION['user_id']]);
            $item_to_edit = $stmt->fetch();
            if (!$item_to_edit) {
                $error = "Item not found or you don't have permission to edit it.";
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
        $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE id = ? AND posted_by = ?");
        $stmt->execute([$item_id, $_SESSION['user_id']]);
        if ($stmt->rowCount() > 0) {
            $success = "Item marked as closed successfully!";
        } else {
            $error = "Item not found or you don't have permission to close it.";
        }
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
        $stmt = $pdo->prepare("UPDATE items SET status = 'open' WHERE id = ? AND posted_by = ?");
        $stmt->execute([$item_id, $_SESSION['user_id']]);
        if ($stmt->rowCount() > 0) {
            $success = "Item reopened successfully!";
        } else {
            $error = "Item not found or you don't have permission to reopen it.";
        }
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
        $pdo->beginTransaction();

        // Fetch the item to get the image path
        $stmt = $pdo->prepare("SELECT image FROM items WHERE id = ? AND posted_by = ?");
        $stmt->execute([$item_id, $_SESSION['user_id']]);
        $item = $stmt->fetch();

        if ($item) {
            // Step 1: Delete related transactions (via offers)
            $stmt = $pdo->prepare("DELETE t FROM transactions t 
                                   JOIN offers o ON t.offer_id = o.id 
                                   WHERE o.item_id = ?");
            $stmt->execute([$item_id]);
            error_log("Deleted transactions for item_id: $item_id");

            // Step 2: Delete related offers
            $stmt = $pdo->prepare("DELETE FROM offers WHERE item_id = ?");
            $stmt->execute([$item_id]);
            error_log("Deleted offers for item_id: $item_id");

            // Step 3: Delete the image file if it exists
            if (!empty($item['image'])) {
                $image_path = dirname(__DIR__) . '/' . $item['image'];
                if (file_exists($image_path)) {
                    unlink($image_path);
                    error_log("Deleted image for item_id: $item_id, path: $image_path");
                }
            }

            // Step 4: Delete the item from the database
            $stmt = $pdo->prepare("DELETE FROM items WHERE id = ? AND posted_by = ?");
            $stmt->execute([$item_id, $_SESSION['user_id']]);
            if ($stmt->rowCount() > 0) {
                $success = "Item, related offers, and transactions deleted successfully!";
                error_log("Item deleted - item_id: $item_id, admin_id: {$_SESSION['user_id']}");
            } else {
                $error = "Item not found or you don't have permission to delete it.";
            }
            $pdo->commit();
        } else {
            $error = "Item not found or you don't have permission to delete it.";
            $pdo->rollBack();
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting item: " . $e->getMessage();
        error_log("Item deletion failed: " . $e->getMessage());
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
            $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
            $user_id = $_SESSION['user_id'];
            $image_path = null;

            if (empty($item_name) || empty($description) || $max_price <= 0 || $quantity <= 0) {
                $error = "All fields are required, and max price/quantity must be positive.";
            } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                $error = "Close time must be in the future.";
            } else {
                if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                    $max_size = 5 * 1024 * 1024; // 5MB
                    $upload_dir = dirname(__DIR__) . '/uploads/';
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
                        $image_path = 'uploads/' . $file_name;
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO buy_requests (user_id, item_name, description, max_price, quantity, status, image, close_time, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, NOW())");
                    $stmt->execute([$user_id, $item_name, $description, $max_price, $quantity, $image_path, $close_time]);
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
        if ($stmt->rowCount() > 0) {
            $success = "Buy request canceled successfully!";
        } else {
            $error = "Buy request not found or you don't have permission to cancel it.";
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error canceling buy request: " . $e->getMessage();
    }
}

// Handle Reopen Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'reopen_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'open' WHERE id = ? AND user_id = ?");
        $stmt->execute([$request_id, $_SESSION['user_id']]);
        if ($stmt->rowCount() > 0) {
            $success = "Buy request reopened successfully!";
        } else {
            $error = "Buy request not found or you don't have permission to reopen it.";
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error reopening buy request: " . $e->getMessage();
    }
}

// Handle Delete Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'delete_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $pdo->beginTransaction();

        // Fetch the buy request to get the image path
        $stmt = $pdo->prepare("SELECT image FROM buy_requests WHERE id = ? AND user_id = ?");
        $stmt->execute([$request_id, $_SESSION['user_id']]);
        $request = $stmt->fetch();

        if ($request) {
            // Step 1: Delete related transactions (via offers)
            $stmt = $pdo->prepare("DELETE t FROM transactions t 
                                   JOIN offers o ON t.offer_id = o.id 
                                   WHERE o.request_id = ?");
            $stmt->execute([$request_id]);
            error_log("Deleted transactions for request_id: $request_id");

            // Step 2: Delete related offers
            $stmt = $pdo->prepare("DELETE FROM offers WHERE request_id = ?");
            $stmt->execute([$request_id]);
            error_log("Deleted offers for request_id: $request_id");

            // Step 3: Delete the image file if it exists
            if (!empty($request['image'])) {
                $image_path = dirname(__DIR__) . '/' . $request['image'];
                if (file_exists($image_path)) {
                    unlink($image_path);
                    error_log("Deleted image for request_id: $request_id, path: $image_path");
                }
            }

            // Step 4: Delete the buy request from the database
            $stmt = $pdo->prepare("DELETE FROM buy_requests WHERE id = ? AND user_id = ?");
            $stmt->execute([$request_id, $_SESSION['user_id']]);
            if ($stmt->rowCount() > 0) {
                $success = "Buy request, related offers, and transactions deleted successfully!";
                error_log("Buy request deleted - request_id: $request_id, admin_id: {$_SESSION['user_id']}");
            } else {
                $error = "Buy request not found or you don't have permission to delete it.";
            }
            $pdo->commit();
        } else {
            $error = "Buy request not found or you don't have permission to delete it.";
            $pdo->rollBack();
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting buy request: " . $e->getMessage();
        error_log("Buy request deletion failed: " . $e->getMessage());
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
            WHERE o.request_id = ? AND o.status = 'pending' AND br.user_id = ?");
        $stmt->execute([$request_id, $_SESSION['user_id']]);
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
        $pdo->beginTransaction();

        // Step 1: Delete related transactions
        $stmt = $pdo->prepare("DELETE FROM transactions WHERE offer_id = ?");
        $stmt->execute([$offer_id]);
        error_log("Deleted transactions for offer_id: $offer_id");

        // Step 2: Delete the offer
        $stmt = $pdo->prepare("DELETE FROM offers WHERE id = ?");
        $stmt->execute([$offer_id]);
        if ($stmt->rowCount() > 0) {
            $success = "Offer and related transactions deleted successfully!";
            error_log("Offer deleted - offer_id: $offer_id");
        } else {
            $error = "Offer not found.";
        }
        $pdo->commit();

        header("Location: admin_dashboard.php?action=offers");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting offer: " . $e->getMessage();
        error_log("Offer deletion failed: " . $e->getMessage());
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

// Handle Report Generation and Export
if (isset($_GET['action']) && $_GET['action'] == 'report' && isset($_GET['generate_report'])) {
    $start_date = $_POST['start_date'] ?? '';
    $end_date = $_POST['end_date'] ?? '';
    $transaction_type = $_POST['transaction_type'] ?? 'all';
    $status = $_POST['status'] ?? 'all';

    // Validate dates
    if ($start_date && $end_date) {
        $start_date = date('Y-m-d 00:00:00', strtotime($start_date));
        $end_date = date('Y-m-d 23:59:59', strtotime($end_date));
        if (strtotime($start_date) > strtotime($end_date)) {
            $error = "Start date must be earlier than end date.";
        }
    } else {
        $start_date = null;
        $end_date = null;
    }

    if (!isset($error)) {
        try {
            // Build the base query for transactions
            $query = "SELECT t.*, 
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
            WHERE (i.posted_by = ? OR br.user_id = ?)";

            $params = [$_SESSION['user_id'], $_SESSION['user_id']];

            // Apply date filters
            if ($start_date && $end_date) {
                $query .= " AND t.created_at BETWEEN ? AND ?";
                $params[] = $start_date;
                $params[] = $end_date;
            }

            // Apply transaction type filter
            if ($transaction_type !== 'all') {
                if ($transaction_type == 'sell') {
                    $query .= " AND t.item_id IS NOT NULL";
                } elseif ($transaction_type == 'buy') {
                    $query .= " AND t.request_id IS NOT NULL";
                }
            }

            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            $report_transactions = $stmt->fetchAll();

            // Fetch items for inventory report
            $items_query = "SELECT i.*, u.username AS posted_by_name 
                FROM items i 
                JOIN users u ON i.posted_by = u.id 
                WHERE i.posted_by = ?";
            $items_params = [$_SESSION['user_id']];
            if ($start_date && $end_date) {
                $items_query .= " AND i.created_at BETWEEN ? AND ?";
                $items_params[] = $start_date;
                $items_params[] = $end_date;
            }
            if ($status !== 'all') {
                $items_query .= " AND i.status = ?";
                $items_params[] = $status;
            }
            $stmt = $pdo->prepare($items_query);
            $stmt->execute($items_params);
            $report_items = $stmt->fetchAll();

            // Fetch buy requests for report
            $requests_query = "SELECT br.*, u.username 
                FROM buy_requests br 
                JOIN users u ON br.user_id = u.id 
                WHERE br.user_id = ?";
            $requests_params = [$_SESSION['user_id']];
            if ($start_date && $end_date) {
                $requests_query .= " AND br.created_at BETWEEN ? AND ?";
                $requests_params[] = $start_date;
                $requests_params[] = $end_date;
            }
            if ($status !== 'all') {
                $requests_query .= " AND br.status = ?";
                $requests_params[] = $status;
            }
            $stmt = $pdo->prepare($requests_query);
            $stmt->execute($requests_params);
            $report_requests = $stmt->fetchAll();

            // Handle CSV export
            if (isset($_POST['export_csv'])) {
                header('Content-Type: text/csv');
                header('Content-Disposition: attachment; filename="admin_report_' . date('Y-m-d_H-i-s') . '.csv"');

                $output = fopen('php://output', 'w');

                // Write Transactions Section
                fputcsv($output, ['Transactions Report']);
                fputcsv($output, ['ID', 'Item Name', 'Type', 'Buyer', 'Seller', 'Supplier', 'Original Price/Max Price', 'Final Price', 'Quantity', 'Total Amount', 'Description', 'Date']);
                foreach ($report_transactions as $t) {
                    $item_name = $t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A';
                    $type = $t['item_id'] ? 'Sell' : 'Buy';
                    $supplier = $t['supplier_name_sell'] ?? 'N/A';
                    $original_price = $t['item_id'] ? ($t['original_price_sell'] ?? 'N/A') : ($t['max_price_buy'] ?? 'N/A');
                    $description = $t['description_sell'] ?? $t['description_buy'] ?? 'N/A';
                    $total_amount = $t['final_price'] * $t['quantity'];
                    fputcsv($output, [
                        $t['id'],
                        $item_name,
                        $type,
                        $t['buyer'],
                        $t['seller'],
                        $supplier,
                        $original_price,
                        $t['final_price'],
                        $t['quantity'],
                        $total_amount,
                        $description,
                        $t['created_at']
                    ]);
                }

                // Write Inventory Section
                fputcsv($output, []);
                fputcsv($output, ['Inventory Report']);
                fputcsv($output, ['ID', 'Item Name', 'Supplier', 'Description', 'Price', 'Quantity', 'Status', 'Posted By', 'Created At']);
                foreach ($report_items as $item) {
                    fputcsv($output, [
                        $item['id'],
                        $item['item_name'],
                        $item['supplier_name'] ?? 'N/A',
                        $item['description'],
                        $item['price'],
                        $item['quantity'],
                        $item['status'],
                        $item['posted_by_name'],
                        $item['created_at']
                    ]);
                }

                // Write Buy Requests Section
                fputcsv($output, []);
                fputcsv($output, ['Buy Requests Report']);
                fputcsv($output, ['ID', 'Item Name', 'Description', 'Max Price', 'Quantity', 'Status', 'User', 'Created At']);
                foreach ($report_requests as $request) {
                    fputcsv($output, [
                        $request['id'],
                        $request['item_name'],
                        $request['description'],
                        $request['max_price'],
                        $request['quantity'],
                        $request['status'],
                        $request['username'],
                        $request['created_at']
                    ]);
                }

                fclose($output);
                exit();
            }
        } catch (PDOException $e) {
            $error = "Error generating report: " . $e->getMessage();
        }
    }
}

// Fetch counts for dashboard
$items_for_sell = $buy_requests = $pending_offers = 0;
try {
    // Count all items for admin (not just posted_by)
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM items WHERE posted_by = ?");
    $stmt->execute([$_SESSION['user_id']]);
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
    $stmt = $pdo->prepare("SELECT item_name FROM items WHERE quantity < ? AND status = 'open' AND posted_by = ?");
    $stmt->execute([$min_stock, $_SESSION['user_id']]);
    $low_stock_items = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $error = "Error fetching low stock items: " . $e->getMessage();
}

// Fetch items for sale (only items posted by this admin)
$items = [];
try {
    $stmt = $pdo->prepare("SELECT i.*, u.username AS posted_by_name 
        FROM items i 
        JOIN users u ON i.posted_by = u.id 
        WHERE i.posted_by = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $items = $stmt->fetchAll();
    error_log("Fetched items: " . count($items));
} catch (PDOException $e) {
    $error = "Error fetching items: " . $e->getMessage();
}

// Fetch buy requests
$requests = [];
try {
    $stmt = $pdo->prepare("SELECT br.*, u.username 
        FROM buy_requests br 
        JOIN users u ON br.user_id = u.id 
        WHERE br.user_id = ?");
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
   
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <script src="../javaScript/scripts.js"></script>

</head>

<body>
    

<!-- Navbar -->
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
                <a href="admin_dashboard.php" class="active">Dashboard</a>
                <a href="logout.php">Logout</a>
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
                            <label for="close_time">Close Time (optional):</label>
                            <input type="datetime-local" name="close_time" id="close_time" class="input" />
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
    <?php if (isset($error)): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <form method="POST" enctype="multipart/form-data">
        <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? ''); ?>">
        <div class="form-group">
            <label>Supplier Name:</label>
            <input type="text" name="supplier_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['supplier_name'] ?? ''); ?>" required />
        </div>
        <div class="form-group">
            <label>Item Name:</label>
            <input type="text" name="item_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['item_name'] ?? ''); ?>" required />
        </div>
        <div class="form-group">
            <label>Description:</label>
            <textarea name="description" class="input" rows="4" required><?php echo htmlspecialchars($item_to_edit['description'] ?? ''); ?></textarea>
        </div>
        <div class="form-group">
            <label>Price ($):</label>
            <input type="number" name="price" class="input" value="<?php echo htmlspecialchars($item_to_edit['price'] ?? 0); ?>" step="0.01" required />
        </div>
        <div class="form-group">
            <label>Quantity:</label>
            <input type="number" name="quantity" class="input" value="<?php echo htmlspecialchars($item_to_edit['quantity'] ?? 0); ?>" required />
        </div>
        <div class="form-group">
            <label>Close Time (optional):</label>
            <input type="datetime-local" name="close_time" id="close_time" class="input" value="<?php echo !empty($item_to_edit['close_time']) && strtotime($item_to_edit['close_time']) ? date('Y-m-d\TH:i', strtotime($item_to_edit['close_time'])) : ''; ?>" />
        </div>
        <div class="form-group">
            <label>Current Image:</label>
            <?php if (!empty($item_to_edit['image']) && file_exists('../' . $item_to_edit['image'])): ?>
                <img src="../<?php echo htmlspecialchars($item_to_edit['image']); ?>" alt="Current Image" class="item-image" style="max-width: 200px;">
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
                            <label for="close_time">Close Time (optional):</label>
                            <input type="datetime-local" name="close_time" id="close_time" class="input" />
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
                                    <?php if (!empty($item['close_time']) && $item['status'] === 'open'): ?>
                                        <p class="countdown" data-close-time="<?php echo htmlspecialchars($item['close_time']); ?>">
                                            Closes in: <span class="countdown-timer"></span>
                                        </p>
                                    <?php elseif (!empty($item['close_time'])): ?>
                                        <p><strong>Closed At:</strong> <?php echo htmlspecialchars($item['close_time']); ?></p>
                                    <?php endif; ?>
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
                                        <a href="?action=delete_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to permanently delete this item? All related offers and transactions will also be deleted, and this action cannot be undone.');">
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
                                    <?php if (!empty($request['close_time']) && $request['status'] === 'open'): ?>
                                        <p class="countdown" data-close-time="<?php echo htmlspecialchars($request['close_time']); ?>">
                                            Closes in: <span class="countdown-timer"></span>
                                        </p>
                                    <?php elseif (!empty($request['close_time'])): ?>
                                        <p><strong>Closed At:</strong> <?php echo htmlspecialchars($request['close_time']); ?></p>
                                    <?php endif; ?>
                                    <div class="item-details">
                                        <p><strong>Posted By:</strong> <?php echo htmlspecialchars($request['username']); ?></p>
                                        <p><strong>Created At:</strong> <?php echo htmlspecialchars($request['created_at'] ?? 'N/A'); ?></p>
                                        <p><strong>Status:</strong> <?php echo htmlspecialchars($request['status'] ?? 'N/A'); ?></p>
                                    </div>
                                    <div class="item-actions">
                                        <a href="?action=view_offers&request_id=<?php echo $request['id']; ?>" class="admin-btn">
                                            <i class="fas fa-search"></i> View Offers
                                        </a>
                                        <?php if ($request['status'] !== 'closed'): ?>
                                            <a href="?action=cancel_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to mark this buy request as closed? It will no longer be available for offers, but will remain in your records.');">
                                                <i class="fas fa-times"></i> Mark as Closed
                                            </a>
                                        <?php else: ?>
                                            <a href="?action=reopen_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn reopen" onclick="return confirm('Are you sure you want to reopen this buy request? It will become available for offers again.');">
                                                <i class="fas fa-undo"></i> Reopen
                                            </a>
                                        <?php endif; ?>
                                        <a href="?action=delete_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to permanently delete this buy request? All related offers and transactions will also be deleted, and this action cannot be undone.');">
                                            <i class="fas fa-trash"></i> Delete
                                        </a>
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

                <?php elseif ($_GET['action'] == 'view_offers' && isset($buy_request_offers)): ?>
                <!-- View Offers for Buy Request -->
                <h2><i class="fas fa-exchange-alt"></i> Offers for Buy Request</h2>
                <?php if ($buy_request_offers): ?>
                    <div class="offers-table-container">
                        <table class="offers-table">
                            <thead>
                                <tr>
                                    <th>From</th>
                                    <th>Item Name</th>
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
                                        <td><?php echo htmlspecialchars($offer['item_name']); ?></td>
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
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? All related transactions will also be deleted, and this action cannot be undone.');">
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
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? All related transactions will also be deleted, and this action cannot be undone.');">
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
                                    <th>Item Name</th>
                                    <th>From</th>
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
                                            <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer? All related transactions will also be deleted, and this action cannot be undone.');">
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
                <h2><i class="fas fa-receipt"></i> Transactions (<?php echo count($transactions); ?>)</h2>
                <?php if ($transactions): ?>
                    <div class="offers-table-container">
                        <table class="offers-table">
                            <thead>
                                <tr>
                                    <th>Transaction ID</th>
                                    <th>Item Name</th>
                                    <th>Type</th>
                                    <th>Buyer</th>
                                    <th>Seller</th>
                                    <th>Final Price ($)</th>
                                    <th>Quantity</th>
                                    <th>Total Amount ($)</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($transactions as $t): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($t['id']); ?></td>
                                        <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A'); ?></td>
                                        <td><?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></td>
                                        <td><?php echo htmlspecialchars($t['buyer']); ?></td>
                                        <td><?php echo htmlspecialchars($t['seller'] ?? 'N/A'); ?></td>
                                        <td>$<?php echo number_format($t['final_price'], 2); ?></td>
                                        <td><?php echo htmlspecialchars($t['quantity']); ?></td>
                                        <td>$<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></td>
                                        <td><?php echo htmlspecialchars($t['created_at']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="no-data">
                        <i class="fas fa-receipt"></i>
                        <p>No transactions recorded.</p>
                    </div>
                <?php endif; ?>

            <?php elseif ($_GET['action'] == 'report'): ?>
                <!-- Reports -->
                <h2><i class="fas fa-chart-pie"></i> Generate Report</h2>
                <div class="form-card">
                    <h3>Filter Report</h3>
                    <form method="POST" action="?action=report&generate_report=1" class="report-form">
                        <div class="form-group">
                            <label for="start_date">Start Date:</label>
                            <input type="date" name="start_date" id="start_date" class="input" />
                        </div>
                        <div class="form-group">
                            <label for="end_date">End Date:</label>
                            <input type="date" name="end_date" id="end_date" class="input" />
                        </div>
                        <div class="form-group">
                            <label for="transaction_type">Transaction Type:</label>
                            <select name="transaction_type" id="transaction_type" class="input">
                                <option value="all">All</option>
                                <option value="sell">Sell Transactions</option>
                                <option value="buy">Buy Transactions</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="status">Status:</label>
                            <select name="status" id="status" class="input">
                                <option value="all">All</option>
                                <option value="open">Open</option>
                                <option value="closed">Closed</option>
                            </select>
                        </div>
                        <button type="submit" class="admin-btn">Generate Report</button>
                        <button type="submit" name="export_csv" value="1" class="admin-btn export">Export to CSV</button>
                    </form>
                </div>

                <?php if (isset($report_transactions)): ?>
                    <!-- Transactions Report -->
                    <h3>Transactions Report</h3>
                    <?php if ($report_transactions): ?>
                        <div class="report-table-container">
                            <table class="report-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Item Name</th>
                                        <th>Type</th>
                                        <th>Buyer</th>
                                        <th>Seller</th>
                                        <th>Supplier</th>
                                        <th>Original Price/Max Price ($)</th>
                                        <th>Final Price ($)</th>
                                        <th>Quantity</th>
                                        <th>Total Amount ($)</th>
                                        <th>Description</th>
                                        <th>Date</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($report_transactions as $t): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($t['id']); ?></td>
                                            <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A'); ?></td>
                                            <td><?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></td>
                                            <td><?php echo htmlspecialchars($t['buyer']); ?></td>
                                            <td><?php echo htmlspecialchars($t['seller'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($t['supplier_name_sell'] ?? 'N/A'); ?></td>
                                            <td>$<?php echo number_format($t['item_id'] ? ($t['original_price_sell'] ?? 0) : ($t['max_price_buy'] ?? 0), 2); ?></td>
                                            <td>$<?php echo number_format($t['final_price'], 2); ?></td>
                                            <td><?php echo htmlspecialchars($t['quantity']); ?></td>
                                            <td>$<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></td>
                                            <td><?php echo htmlspecialchars($t['description_sell'] ?? $t['description_buy'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($t['created_at']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="no-data">
                            <i class="fas fa-receipt"></i>
                            <p>No transactions match the selected criteria.</p>
                        </div>
                    <?php endif; ?>

                    <!-- Inventory Report -->
                    <h3>Inventory Report</h3>
                    <?php if ($report_items): ?>
                        <div class="report-table-container">
                            <table class="report-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Item Name</th>
                                        <th>Supplier</th>
                                        <th>Description</th>
                                        <th>Price ($)</th>
                                        <th>Quantity</th>
                                        <th>Status</th>
                                        <th>Posted By</th>
                                        <th>Created At</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($report_items as $item): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($item['id']); ?></td>
                                            <td><?php echo htmlspecialchars($item['item_name']); ?></td>
                                            <td><?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($item['description']); ?></td>
                                            <td>$<?php echo number_format($item['price'], 2); ?></td>
                                            <td><?php echo htmlspecialchars($item['quantity']); ?></td>
                                            <td><?php echo htmlspecialchars($item['status']); ?></td>
                                            <td><?php echo htmlspecialchars($item['posted_by_name']); ?></td>
                                            <td><?php echo htmlspecialchars($item['created_at']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="no-data">
                            <i class="fas fa-box-open"></i>
                            <p>No items match the selected criteria.</p>
                        </div>
                    <?php endif; ?>

                    <!-- Buy Requests Report -->
                    <h3>Buy Requests Report</h3>
                    <?php if ($report_requests): ?>
                        <div class="report-table-container">
                            <table class="report-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Item Name</th>
                                        <th>Description</th>
                                        <th>Max Price ($)</th>
                                        <th>Quantity</th>
                                        <th>Status</th>
                                        <th>User</th>
                                        <th>Created At</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($report_requests as $request): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($request['id']); ?></td>
                                            <td><?php echo htmlspecialchars($request['item_name']); ?></td>
                                            <td><?php echo htmlspecialchars($request['description']); ?></td>
                                            <td>$<?php echo number_format($request['max_price'], 2); ?></td>
                                            <td><?php echo htmlspecialchars($request['quantity']); ?></td>
                                            <td><?php echo htmlspecialchars($request['status']); ?></td>
                                            <td><?php echo htmlspecialchars($request['username']); ?></td>
                                            <td><?php echo htmlspecialchars($request['created_at']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="no-data">
                            <i class="fas fa-hand-holding-usd"></i>
                            <p>No buy requests match the selected criteria.</p>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

            <?php endif; ?>
        </div>
    </div>

    <!-- Footer -->
    <footer>
        <div class="copyright">
            © 2024 | Created & Designed By <a href="#home">Group 8</a>
        </div>
        <div class="sm">
            <a href="#/"><i class="fa fa-facebook" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-instagram" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-telegram" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-github" style="font-size:24px"></i></a>
        </div>
    </footer>

    <script>
        // Countdown Timer for Close Time
        document.addEventListener('DOMContentLoaded', function() {
            const countdownElements = document.querySelectorAll('.countdown');
            
            function updateCountdown() {
                countdownElements.forEach(element => {
                    const closeTime = new Date(element.getAttribute('data-close-time')).getTime();
                    const now = new Date().getTime();
                    const distance = closeTime - now;

                    if (distance <= 0) {
                        element.innerHTML = 'Closed';
                        // Optionally, refresh the page to update status
                        // window.location.reload();
                    } else {
                        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
                        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

                        element.querySelector('.countdown-timer').innerHTML = 
                            `${days}d ${hours}h ${minutes}m ${seconds}s`;
                    }
                });
            }

            // Update countdown every second
            updateCountdown();
            setInterval(updateCountdown, 1000);

            // Toggle sidebar for mobile
            document.querySelector('.menu-toggler').addEventListener('click', function() {
                document.querySelector('.navbar-menu').classList.toggle('active');
            });
        });
    </script>
</body>
</html>